# -*- encoding: utf-8 -*-

# Copyright 2011-2013 Glenn Rempe

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'rubygems'
require 'bundler'
Bundler.setup

# code coverage
begin
  require 'coco'
rescue LoadError
  # Don't blow up with coco isn't available.
  # It won't install on MRI Ruby < 1.9.2 or
  # other platforms. It is not installed
  # in the Travis CI build environment.
end

require File.expand_path('../../lib/secretsharing', __FILE__)
require 'minitest/autorun'
