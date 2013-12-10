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

require File.expand_path('../spec_helper', __FILE__)

describe SecretSharing::Shamir::Share do

  describe 'initialization' do

    it 'will raise when instantiated with no args' do
      lambda { SecretSharing::Shamir::Share.new }.must_raise(ArgumentError)
    end

    it 'will raise if an unknown option hash key is passed in' do
      lambda { SecretSharing::Shamir::Share.new(:foo => 'bar') }.must_raise(ArgumentError)
    end

    it 'will raise when instantiated with missing args' do
      lambda { SecretSharing::Shamir::Share.new(:x => 1, :y => 1, :prime => 1) }.must_raise(ArgumentError)
      lambda { SecretSharing::Shamir::Share.new(:x => 1, :y => 1) }.must_raise(ArgumentError)
      lambda { SecretSharing::Shamir::Share.new(:x => 1) }.must_raise(ArgumentError)
    end

    it 'will be instantiated when provided with complete args' do
      @s = SecretSharing::Shamir::Share.new(:x => 1, :y => 1, :prime => 1, :prime_bitlength => 1)
    end

    it 'will be instantiated from a valid String provided to the Share#new method as the first arg' do
      share = '0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341'
      @s = SecretSharing::Shamir::Share.new(:share => share)
      @s.must_be_kind_of(SecretSharing::Shamir::Share)
      @s.to_s.must_equal(share)
    end

    it 'will raise when an otherwise valid String is provided with the VERSION part of the string changed from 0 to 1' do
      @s = SecretSharing::Shamir::Share.new(:share => '0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341')
      @s.must_be_kind_of(SecretSharing::Shamir::Share)
      lambda { @s = SecretSharing::Shamir::Share.new(:share => '1016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341') }.must_raise(RuntimeError)
    end

    it 'will raise when an otherwise valid String is provided with the CHECKSUM part of the string changed modified' do
      @s = SecretSharing::Shamir::Share.new(:share => '0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341')
      @s.must_be_kind_of(SecretSharing::Shamir::Share)
      # changed A0B8 to A1B8
      lambda { @s = SecretSharing::Shamir::Share.new(:share => '0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A1B81341') }.must_raise(RuntimeError)
    end

    it 'will be instantiated from a to_s String provided to the Share#new method' do
      @s = SecretSharing::Shamir::Share.new(:x => 1, :y => 1, :prime => 1, :prime_bitlength => 1)
      @s1 = SecretSharing::Shamir::Share.new(:share => @s.to_s)
    end

    it 'must be able to be compared directly to another share (==)' do
      @s1 = SecretSharing::Shamir::Share.new(:x => 1, :y => 1, :prime => 1, :prime_bitlength => 1)
      @s2 = SecretSharing::Shamir::Share.new(:x => 1, :y => 1, :prime => 1, :prime_bitlength => 1)

      @s1.must_equal(@s2)
    end

  end

end
