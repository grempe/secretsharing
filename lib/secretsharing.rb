# -*- encoding: utf-8 -*-

# Copyright 2011-2015 Glenn Rempe

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Backport support for Bignum#bit_length and Fixnum#bit_length which were added in Ruby 2.1
# See : http://globaldev.co.uk/2014/05/ruby-2-1-in-detail/
# See : https://github.com/marcandre/backports
require 'backports/1.9.1/kernel/require_relative'
require 'backports/2.1.0/bignum/bit_length'
require 'backports/2.1.0/fixnum/bit_length'

require 'rbnacl/libsodium'
require 'rbnacl'
require 'base64'
require 'multi_json'

require 'secretsharing/version'
require 'secretsharing/shamir'
require 'secretsharing/shamir/container'
require 'secretsharing/shamir/share'
require 'secretsharing/shamir/secret'
