# -*- encoding: utf-8 -*-

# Copyright 2011-2014 Glenn Rempe

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

describe SecretSharing::Shamir::Share do

  describe 'initialization' do

    before do
      @args = { :hmac => 'foo', :k => 3, :n => 4, :x => 1, :y => 1, :prime => 1, :prime_bitlength => 1 }
    end

    it 'will raise when instantiated with no args' do
      lambda { SecretSharing::Shamir::Share.new }.must_raise(ArgumentError)
    end

    it 'will raise if an unknown option hash key is passed in' do
      lambda { SecretSharing::Shamir::Share.new(@args.merge(:foo => 'bar')) }.must_raise(ArgumentError)
    end

    it 'will raise when instantiated with missing args' do
      lambda { SecretSharing::Shamir::Share.new(@args.merge(:version => nil)) }.must_raise(ArgumentError)
      lambda { SecretSharing::Shamir::Share.new(@args.merge(:hmac => nil)) }.must_raise(ArgumentError)
      lambda { SecretSharing::Shamir::Share.new(@args.merge(:k => nil)) }.must_raise(ArgumentError)
      lambda { SecretSharing::Shamir::Share.new(@args.merge(:n => nil)) }.must_raise(ArgumentError)
      lambda { SecretSharing::Shamir::Share.new(@args.merge(:x => nil)) }.must_raise(ArgumentError)
      lambda { SecretSharing::Shamir::Share.new(@args.merge(:y => nil)) }.must_raise(ArgumentError)
      lambda { SecretSharing::Shamir::Share.new(@args.merge(:prime => nil)) }.must_raise(ArgumentError)
      lambda { SecretSharing::Shamir::Share.new(@args.merge(:prime_bitlength => nil)) }.must_raise(ArgumentError)
    end

    it 'will be instantiated when provided with complete args' do
      @s = SecretSharing::Shamir::Share.new(:hmac => 'foo', :k => 3, :n => 4, :x => 1, :y => 1, :prime => 1, :prime_bitlength => 1)
      @s.must_be_kind_of(SecretSharing::Shamir::Share)
    end

    it 'must be able to be compared directly to another share (==)' do
      @s1 = SecretSharing::Shamir::Share.new(:hmac => 'foo', :k => 3, :n => 4, :x => 1, :y => 1, :prime => 1, :prime_bitlength => 1)
      @s2 = SecretSharing::Shamir::Share.new(:hmac => 'foo', :k => 3, :n => 4, :x => 1, :y => 1, :prime => 1, :prime_bitlength => 1)
      @s1.must_equal(@s2)
    end

  end

end
