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

# rubocop:disable LineLength

describe SecretSharing::Shamir::Share do

  describe 'initialization' do

    it 'will raise when instantiated with no args' do
      -> { SecretSharing::Shamir::Share.new }.must_raise(ArgumentError)
    end

    it 'will raise when instantiated with missing args' do
      -> { SecretSharing::Shamir::Share.new(1, 1, 1) }.must_raise(ArgumentError)
      -> { SecretSharing::Shamir::Share.new(1, 1) }.must_raise(ArgumentError)
      -> { SecretSharing::Shamir::Share.new(1) }.must_raise(ArgumentError)
    end

    it 'will be instantiated when provided with complete args' do
      @s = SecretSharing::Shamir::Share.new(1, 1, 1, 1)
    end

    it 'will be instantiated from a valid String provided to the Share#new method as the first arg' do
      share = '0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341'
      @s = SecretSharing::Shamir::Share.new(share)
      @s.must_be_kind_of(SecretSharing::Shamir::Share)
      @s.to_s.must_equal(share)
    end

    it 'will be instantiated from a valid String provided to the now deprecated Share#from_string method' do
      share = '0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341'
      @s = SecretSharing::Shamir::Share.from_string(share)
      @s.must_be_kind_of(SecretSharing::Shamir::Share)
      @s.to_s.must_equal(share)
    end

    it 'will raise when an otherwise valid String is provided with the VERSION part of the string changed from 0 to 1' do
      @s = SecretSharing::Shamir::Share.new('0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341')
      @s.must_be_kind_of(SecretSharing::Shamir::Share)
      -> { @s = SecretSharing::Shamir::Share.new('1016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341') }.must_raise(RuntimeError)
    end

    it 'will raise when an otherwise valid String is provided with the CHECKSUM part of the string changed modified' do
      @s = SecretSharing::Shamir::Share.new('0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341')
      @s.must_be_kind_of(SecretSharing::Shamir::Share)
      # changed A0B8 to A1B8
      -> { @s = SecretSharing::Shamir::Share.new('0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A1B81341') }.must_raise(RuntimeError)
    end

    it 'will be instantiated from a to_s String provided to the Share#new method' do
      @s = SecretSharing::Shamir::Share.new(1, 1, 1, 1)
      share = @s.to_s
      @s1 = SecretSharing::Shamir::Share.new(share)
    end

    it 'must be able to be compared directly to another share (==)' do
      @s1 = SecretSharing::Shamir::Share.new(1, 1, 1, 1)
      @s2 = SecretSharing::Shamir::Share.new(1, 1, 1, 1)

      @s1.must_equal(@s2)
    end

  end

end

# rubocop:enable LineLength
