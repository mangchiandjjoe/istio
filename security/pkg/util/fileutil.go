// Copyright 2017 Istio Authors
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

package util

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	identityDirPermission = 0755
)

// FileUtil is the interface for utility functions operating on files.
type FileUtil interface {
	// Read reads the file named by filename and returns all the contents unitl EOF or an error.
	Read(string) ([]byte, error)
	// Write writes data to a file named by filename.
	Write(string, []byte, os.FileMode) error
}

// FileUtilImpl is an implementation of File.
type FileUtilImpl struct {
}

// Read reads the file named by filename and returns all the contents until EOF or an error.
func (f FileUtilImpl) Read(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// Write writes data to a file named by filename.
func (f FileUtilImpl) Write(filename string, content []byte, perm os.FileMode) error {
	// If the destination exists and it should not be a directory
	if stat, err := os.Stat(filename); err == nil && stat.IsDir() {
		return fmt.Errorf("unable to write content to the directory: %v", filename)
	}

	// If the parent path of the destination exists, then it should not be a file
	if stat, err := os.Stat(filepath.Dir(filename)); err == nil {
		if !stat.IsDir() {
			return fmt.Errorf("unable to write content to the destination: %v", filename)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(filename), identityDirPermission); err != nil {
			return fmt.Errorf("unable to write file: %v", err)
		}
	}

	return ioutil.WriteFile(filename, content, perm)
}
