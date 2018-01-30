// Copyright 2018 Istio Authors
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

package main

import (
	"errors"
	"os"

	"github.com/spf13/cobra"
	"istio.io/istio/pkg/log"
	"istio.io/istio/security/cmd/node_agent_k8s/flexvolume/driver"
)

const (
	// TODO(wattli): make it configurable.
	ver string = "1.8"
)

var (
	// RootCmd defines the root command for the driver.
	RootCmd = &cobra.Command{
		Use:   "flexvoldrv",
		Short: "Flex volume driver interface for Node Agent.",
		Long:  "Flex volume driver interface for Node Agent.",
	}

	// InitCmd defines the init command for the driver.
	InitCmd = &cobra.Command{
		Use:   "init",
		Short: "Flex volume init command.",
		Long:  "Flex volume init command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) != 0 {
				log.Error("mount takes 0 args")
				return errors.New("mount takes 0 args")
			}
			return driver.Init(ver)
		},
	}

	// AttachCmd defines the attach command for the driver.
	AttachCmd = &cobra.Command{
		Use:   "attach",
		Short: "Flex volumen attach command.",
		Long:  "Flex volumen attach command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				log.Error("mount takes 2 args")
				return errors.New("mount takes 2 args")
			}
			return driver.Attach(args[0], args[1])
		},
	}

	// DetachCmd defines the detach command for the driver.
	DetachCmd = &cobra.Command{
		Use:   "detach",
		Short: "Flex volume detach command.",
		Long:  "Flex volume detach command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 1 {
				log.Error("mount takes 1 args")
				return errors.New("mount takes 1 args")
			}
			return driver.Detach(args[0])
		},
	}

	// WaitAttachCmd defines the waitattach command for the driver.
	WaitAttachCmd = &cobra.Command{
		Use:   "waitforattach",
		Short: "Flex volume waitforattach command.",
		Long:  "Flex volume waitforattach command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 2 {
				log.Error("mount takes 2 args")
				return errors.New("mount takes 2 args")
			}
			return driver.WaitAttach(args[0], args[1])
		},
	}

	// IsAttachedCmd defines the isattached command
	IsAttachedCmd = &cobra.Command{
		Use:   "isattached",
		Short: "Flex volume isattached command.",
		Long:  "Flex volume isattached command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 2 {
				log.Error("mount takes 2 args")
				return errors.New("mount takes 2 args")
			}
			return driver.IsAttached(args[0], args[1])
		},
	}

	// MountDevCmd defines the Mountdev command
	MountDevCmd = &cobra.Command{
		Use:   "mountdevice",
		Short: "Flex volume unmount command.",
		Long:  "Flex volume unmount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 3 {
				log.Error("mount takes 3 args")
				return errors.New("mount takes 3 args")
			}
			return driver.MountDev(args[0], args[1], args[2])
		},
	}

	// UnmountDevCmd defines the unmountdev command
	UnmountDevCmd = &cobra.Command{
		Use:   "unmountdevice",
		Short: "Flex volume unmount command.",
		Long:  "Flex volume unmount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 1 {
				log.Error("mount takes 1 args")
				return errors.New("mount takes 1 args")
			}
			return driver.UnmountDev(args[0])
		},
	}

	// MountCmd defines the mount command
	MountCmd = &cobra.Command{
		Use:   "mount",
		Short: "Flex volume unmount command.",
		Long:  "Flex volume unmount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 2 {
				log.Error("mount takes 2 args")
				return errors.New("mount takes 2 args")
			}
			return driver.Mount(args[0], args[1])
		},
	}

	// UnmountCmd defines the unmount command
	UnmountCmd = &cobra.Command{
		Use:   "unmount",
		Short: "Flex volume unmount command.",
		Long:  "Flex volume unmount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 1 {
				log.Error("mount takes 1 args")
				return errors.New("mount takes 1 args")
			}
			return driver.Unmount(args[0])
		},
	}
)

func init() {
	RootCmd.AddCommand(InitCmd)
	RootCmd.AddCommand(AttachCmd)
	RootCmd.AddCommand(DetachCmd)
	RootCmd.AddCommand(WaitAttachCmd)
	RootCmd.AddCommand(IsAttachedCmd)
	RootCmd.AddCommand(MountDevCmd)
	RootCmd.AddCommand(UnmountDevCmd)
	RootCmd.AddCommand(MountCmd)
	RootCmd.AddCommand(UnmountCmd)
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		log.Errora(err)
		os.Exit(-1)
	}
}
