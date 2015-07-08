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

require File.expand_path('../spec_helper', __FILE__)

# NOTE : these backport tests are only meaninful when run on
# a Ruby runtime that doesn't natively support Bignum.bit_length
describe 'Bignum#bit_length' do
  include SecretSharing::Shamir

  it 'will return the expected bit_length for multiples of 256' do
    [256, 512, 768, 1024].each do |i|
      r = get_random_number_with_bitlength(i)
      r.bit_length.must_equal(i)
    end
  end

  it 'will return the expected bit_length for multiples of 256 + 1' do
    [257, 513, 769, 1025].each do |i|
      r = get_random_number_with_bitlength(i)
      r.bit_length.must_equal(i)
    end
  end
end

# NOTE : these backport tests are only meaninful when run on
# a Ruby runtime that doesn't natively support Fixnum.bit_length
describe 'Fixnum#bit_length' do
  include SecretSharing::Shamir

  it 'will return the expected bit_length for multiples of 8' do
    [1, 8, 16, 24, 32].each do |i|
      r = get_random_number_with_bitlength(i)
      r.bit_length.must_equal(i)
    end
  end

  it 'will return the expected bit_length for multiples of 8 + 1' do
    [2, 9, 17, 25, 33].each do |i|
      r = get_random_number_with_bitlength(i)
      r.bit_length.must_equal(i)
    end
  end
end
