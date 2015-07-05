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

describe SecretSharing::Shamir do

  include SecretSharing::Shamir

  describe "get_random_number" do

    it "will return a Bignum" do
      r = get_random_number(32)
      r.class.must_equal(Bignum)
    end

    it "will return a Bignum with a size equaling the requested number of Bytes" do
      bytes = 32
      r = get_random_number(32)
      r.class.must_equal(Bignum)
    end

  end

  describe "get_random_number_with_bitlength" do

    it "will return a Bignum" do
      bitlength = 256
      r = get_random_number_with_bitlength(bitlength)
      r.class.must_equal(Bignum)
    end

    it "will return a random number of bitlength bits when bitlength is evenly divisible by 8" do
      bitlength = 256
      r = get_random_number_with_bitlength(bitlength)
      r.bit_length.must_equal(bitlength)
    end

    it "will return a random number of bitlength bits when bitlength is not evenly divisible by 8" do
      bitlength = 257
      r = get_random_number_with_bitlength(bitlength)
      r.bit_length.must_equal(bitlength)
    end

  end

  describe 'usafe_encode64 and usafe_decode64' do

    it 'will encode and decode back to the original String' do
      str = MultiJson.dump(:foo => 'bar', :bar => 12_345_678_748_390_743_789)
      enc = usafe_encode64(str)
      dec = usafe_decode64(enc)
      dec.must_equal(str)
    end

  end

end
