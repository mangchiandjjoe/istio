// Copyright 2017 Istio Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package redisquota provides a quota implementation with redis as backend.
// The prerequisite is to have a redis server running.
package redisquota

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"time"

	"github.com/go-redis/redis"
	"istio.io/istio/mixer/adapter/redisquota/config"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/quota"
)

// LUA rate-limiting algorithm scripts
var (
	rateLimitingLUAScripts = map[string]string{
		// LUA script for fixed window
		// ---------------------------------------------------------------------
		"fixed-window": `
local key_meta = KEYS[1]
local key_data = KEYS[2]

local credit = tonumber(ARGV[1])
local windowLength = tonumber(ARGV[2])
local bucketLength = tonumber(ARGV[3])
local bestEffort = tonumber(ARGV[4])
local token = tonumber(ARGV[5])
local timestamp = tonumber(ARGV[6])
local expire = tonumber(ARGV[7])

-- read or initialize meta information
--------------------------------------------------------------------------------
local info_token = redis.call("HGET", key_meta, "token")
local info_expire = tonumber(redis.call("HGET", key_meta, "expire"))

if (not info_token and not info_expire) or (timestamp >= info_expire) then
  info_token = 0
  redis.call("HMSET", key_meta, "token", info_token, "expire", windowLength + timestamp)
	-- set the expiration time for automatic cleanup
	redis.call("EXPIRE", key_meta, expire)
end

if info_token + token > credit then
  if bestEffort == 1 then
    local exceeded = info_token + token - credit

    if exceeded < token then
      -- return maximum possible allocated token
      redis.call("HMSET", key_meta, "token", credit)
      return token - exceeded
    else
      -- not enough available credit
      return 0
    end
  else
    -- not enough available credit
    return 0
  end
else
  -- allocated token
  redis.call("HMSET", key_meta, "token", info_token + token)
  return token
end
`,
		// LUA script for rolling-window algorithm
		// ---------------------------------------------------------------------
		"rolling-window": `
local key_meta = KEYS[1]
local key_data = KEYS[2]

local credit = tonumber(ARGV[1])
local windowLength = tonumber(ARGV[2])
local bucketLength = tonumber(ARGV[3])
local bestEffort = tonumber(ARGV[4])
local token = tonumber(ARGV[5])
local timestamp = tonumber(ARGV[6])
local expire = tonumber(ARGV[7])

-- read meta information
--------------------------------------------------------------------------------
local info_token = redis.call("HGET", key_meta, "token")
local info_bucket_token = redis.call("HGET", key_meta, "bucket.token")
local info_bucket_timestamp = redis.call("HGET", key_meta, "bucket.timestamp")

-- initialize meta
--------------------------------------------------------------------------------
if not info_token or not info_bucket_token or not info_bucket_timestamp then
  info_token = 0
  info_bucket_token = 0
  info_bucket_timestamp = timestamp

  redis.call("HMSET", key_meta,
    "token", info_token,
    "bucket.token", info_bucket_token,
    "bucket.timestamp", info_bucket_timestamp,
    "key", 0)
end

-- move buffer to bucket list if bucket timer is older than bucket window
--------------------------------------------------------------------------------
if (timestamp - info_bucket_timestamp + 1) > bucketLength then
  if tonumber(info_bucket_token) > 0 then
    local nextKey = redis.call("HINCRBY", key_meta, "key", 1)
    local value = tostring(nextKey) .. "." .. tostring(info_bucket_token)
    redis.call("ZADD", key_data, info_bucket_timestamp, value);
  end
  redis.call("HMSET", key_meta,
    "bucket.token", 0,
    "bucket.timestamp", timestamp)
end

local time_to_expire = timestamp - windowLength

		-- reclaim tokens from expired records
--------------------------------------------------------------------------------
local reclaimed = 0
local expired = redis.call("ZRANGEBYSCORE", key_data, 0, time_to_expire)

for idx, value in ipairs(expired) do
  reclaimed = reclaimed + tonumber(string.sub(value, string.find(value, "%.")+1))
end

-- remove expired records
--------------------------------------------------------------------------------
redis.call("ZREMRANGEBYSCORE", key_data, 0, time_to_expire)

-- update consumed token
--------------------------------------------------------------------------------
if reclaimed > 0 then
  info_token = info_token - reclaimed;
  if info_token < 0 then
    info_token = 0
  end
  redis.call("HSET", key_meta, "token", info_token)
end

-- set the expiration time for automatic cleanup
--------------------------------------------------------------------------------
redis.call("EXPIRE", key_meta, expire)
redis.call("EXPIRE", key_meta, expire)

-- calculate available token
--------------------------------------------------------------------------------
local available_token = credit - info_token

-- check available token and requested token
--------------------------------------------------------------------------------
if available_token <= 0 then
  -- credit exhausted
  return 0
elseif available_token >= token then
  -- increase token and bucket.token by token
  redis.call("HINCRBY", key_meta, "token", token)
  redis.call("HINCRBY", key_meta, "bucket.token", token)

  return token
else
  if bestEffort == 0 then
    -- not enough token
    return 0
  end

  -- allocate available token only
  redis.call("HINCRBY", key_meta, "token", available_token)
  redis.call("HINCRBY", key_meta, "bucket.token", available_token)

  return available_token
end
`,
	}
)

type (
	builder struct {
		quotaTypes    map[string]*quota.Type
		adapterConfig *config.Params
	}

	handler struct {
		// go-redis client
		// connection pool with redis
		client *redis.Client

		// the limits we know about
		limits map[string]*config.Params_Quota

		//
		scripts map[string]*redis.Script

		// indirection to support fast deterministic tests
		getTime func() time.Time

		// logger provided by the framework
		logger adapter.Logger
	}
)

///////////////// Configuration Methods ///////////////

func (b *builder) SetQuotaTypes(quotaTypes map[string]*quota.Type) {
	b.quotaTypes = quotaTypes
}

func (b *builder) SetAdapterConfig(cfg adapter.Config) {
	b.adapterConfig = cfg.(*config.Params)
}

func (b *builder) Validate() (ce *adapter.ConfigErrors) {
	if len(b.adapterConfig.RedisServerUrl) == 0 {
		ce = ce.Appendf("redisServerUrl", "redis server url should not be empty")
	}

	if b.adapterConfig.ConnectionPoolSize < 0 {
		ce = ce.Appendf("connectionPoolSize",
			"redis connection pool size of %v is invalid, must be > 0",
			b.adapterConfig.ConnectionPoolSize)
	}

	return
}

func (b *builder) Build(context context.Context, env adapter.Env) (adapter.Handler, error) {
	ac := b.adapterConfig

	limits := make(map[string]*config.Params_Quota, len(ac.Quotas))
	for idx := range ac.Quotas {
		l := ac.Quotas[idx]
		limits[l.Name] = &l
	}

	for k := range b.quotaTypes {
		if _, ok := limits[k]; !ok {
			return nil, env.Logger().Errorf("did not find limit defined for quota %s", k)
		}
	}

	option := redis.Options{
		Addr: b.adapterConfig.RedisServerUrl,
	}

	if b.adapterConfig.ConnectionPoolSize > 0 {
		option.PoolSize = int(b.adapterConfig.ConnectionPoolSize)
	}

	// initialize client
	client := redis.NewClient(&option)

	// test connection
	_, err := client.Ping().Result()
	if err != nil {
		return nil, env.Logger().Errorf("could not create a connection pool with redis: %v", err)
	}

	// load script
	scripts := map[string]*redis.Script{}
	for algorithm, script := range rateLimitingLUAScripts {
		scripts[algorithm] = redis.NewScript(script)
		_, err := scripts[algorithm].Load(client).Result()
		if err != nil {
			return nil, env.Logger().Errorf("unable to load the LUA script: %v", err)
		}
	}

	h := &handler{
		client:  client,
		limits:  limits,
		scripts: scripts,
		logger:  env.Logger(),
		getTime: time.Now,
	}

	return h, nil
}

////////////////// Runtime Methods //////////////////////////

// matchDimensions matches configured dimensions with dimensions of the instance.
func matchDimensions(cfg map[string]string, inst map[string]interface{}) bool {
	for k, val := range cfg {
		rval := inst[k]
		if rval == val { // this dimension matches, on to next comparison.
			continue
		}

		// if rval has a string representation then compare it with val
		// For example net.ip has a useful string representation.
		switch v := rval.(type) {
		case fmt.Stringer:
			if v.String() == val {
				continue
			}
		}
		// rval does not match val.
		return false
	}
	return true
}

func getOverrideHash(cfg map[string]string) string {
	h := sha1.New()
	for key, val := range cfg {
		io.WriteString(h, key+"="+val)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func getAllocatedTokenFromResult(result interface{}) (int64, error) {
	if _, ok := result.([]interface{}); ok {
		if reflect.ValueOf(result).Len() != 1 {
			return 0, fmt.Errorf("invalid response from the redis server: %v", result)
		}
		if value, ok := reflect.ValueOf(result).Index(0).Interface().(string); ok {
			converted, err := strconv.Atoi(value)
			if err != nil {
				return 0, fmt.Errorf("invalid response from the redis server: %v, err: %v", result, err)
			}
			return int64(converted), nil
		}
	}
	return 0, fmt.Errorf("invalid response from the redis server: %v", result)
}

// find override
func (h *handler) getKeyAndQuotaAmount(instance *quota.Instance, args adapter.QuotaArgs, quota *config.Params_Quota) (string, int64) {
	maxAmount := quota.MaxAmount
	key := quota.Name + "-" + args.DeduplicationID

	for idx := range quota.Overrides {
		o := quota.Overrides[idx]
		if matchDimensions(o.Dimensions, instance.Dimensions) {
			if h.logger.VerbosityLevel(4) {
				h.logger.Infof("quota override: %v selected for %v", o, *instance)
			}
			maxAmount = o.MaxAmount
			key = key + "-" + getOverrideHash(o.Dimensions)
		}
	}

	return key, maxAmount
}

func (h *handler) HandleQuota(context context.Context, instance *quota.Instance, args adapter.QuotaArgs) (adapter.QuotaResult, error) {
	now := h.getTime()
	if limit, ok := h.limits[instance.Name]; ok {
		if script, ok := h.scripts[limit.RateLimitAlgorithm]; ok {
			ret := status.OK

			// get overridden quotaAmount and quotaKey
			key, maxAmount := h.getKeyAndQuotaAmount(instance, args, limit)

			// Run lum algorithm script
			result, err := script.Run(
				h.client,
				[]string{
					key + ".meta", // KEY[1] key
					key + ".data", // KEY[2] hash of overrides
				},
				maxAmount, // ARGV[1] credit
				limit.GetValidDuration().Nanoseconds(),  // ARGV[2] window length
				limit.GetBucketDuration().Nanoseconds(), // ARGV[3] bucket length
				args.BestEffort,                         // ARGV[4] best effort
				args.QuotaAmount,                        // ARGV[5] token
				now.UnixNano(),                          // ARGV[6] timestamp
				limit.GetValidDuration().Seconds(),      // ARGV[7] expire
			).Result()

			if err != nil {
				h.logger.Errorf("failed to run quota script: %v", err)
				return adapter.QuotaResult{Status: status.OK}, nil
			}

			allocated, err := getAllocatedTokenFromResult(result)
			if err != nil {
				h.logger.Errorf("%v", err)
				return adapter.QuotaResult{Status: status.OK}, nil
			}

			if allocated <= 0 {
				ret = status.WithResourceExhausted("redisquota: Resource exhausted")
			}

			return adapter.QuotaResult{
				Status: ret,
				Amount: int64(allocated),
			}, nil
		}
	}

	return adapter.QuotaResult{Status: status.OK}, nil
}

func (h handler) Close() error {
	return h.client.Close()
}

////////////////// Bootstrap //////////////////////////

// GetInfo returns the Info associated with this adapter implementation.
func GetInfo() adapter.Info {
	return adapter.Info{
		Name:        "redisquota",
		Impl:        "istio.io/mixer/adapter/redisquota",
		Description: "Redis-based quotas.",
		SupportedTemplates: []string{
			quota.TemplateName,
		},
		DefaultConfig: &config.Params{
			RedisServerUrl:     "localhost:6379",
			ConnectionPoolSize: 10,
		},
		NewBuilder: func() adapter.HandlerBuilder { return &builder{} },
	}
}

///////////////////////////////////////////////////////
