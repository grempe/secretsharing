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

describe SecretSharing::Shamir::Container do

  describe 'initialization' do

    it 'will raise when instantiated with no args' do
      lambda { SecretSharing::Shamir::Container.new }.must_raise(ArgumentError)
    end

    it 'will create shares with n and k equal when given one Integer arg' do
      s1 = SecretSharing::Shamir::Container.new(5)
      s1.n.must_equal(5)
      s1.k.must_equal(5)
    end

    it 'will create shares with n and k set to their own values when given two Integer args' do
      s1 = SecretSharing::Shamir::Container.new(5, 3)
      s1.n.must_equal(5)
      s1.k.must_equal(3)
    end

    it 'will create shares with n and k equal when given one Integer as String arg' do
      s1 = SecretSharing::Shamir::Container.new('5')
      s1.n.must_equal(5)
      s1.k.must_equal(5)
    end

    it 'will raise an exception with n being a non-Integer String arg' do
      lambda { SecretSharing::Shamir::Container.new('foo') }.must_raise(ArgumentError)
    end

    it 'will create shares with n and k set to their own values when given two Integer as String args' do
      s1 = SecretSharing::Shamir::Container.new('5', '3')
      s1.n.must_equal(5)
      s1.k.must_equal(3)
    end

    it 'will return false when secret? is called after initialization with only n arg set' do
      s1 = SecretSharing::Shamir::Container.new(5)
      s1.secret?.must_equal(false)
    end

    it 'will return false when secret? is called after initialization with n and k arg set' do
      s1 = SecretSharing::Shamir::Container.new(5, 3)
      s1.secret?.must_equal(false)
    end

    it 'will return nil secret when called after initialization with only n arg set' do
      s1 = SecretSharing::Shamir::Container.new(5)
      s1.secret.must_be_nil
    end

    it 'will return nil secret when called after initialization with n and k arg set' do
      s1 = SecretSharing::Shamir::Container.new(5, 3)
      s1.secret.must_be_nil
    end

    it 'will raise if k > n' do
      lambda { SecretSharing::Shamir::Container.new(5, 6) }.must_raise(ArgumentError)
    end

    it 'will raise if only n is provided and it is < 2' do
      lambda { SecretSharing::Shamir::Container.new(1) }.must_raise(ArgumentError)
    end

    it 'will raise unless k >= 2' do
      lambda { SecretSharing::Shamir::Container.new(1, 1) }.must_raise(ArgumentError)
    end

    it 'will initialize if both k and n are at max size of 512' do
      s1 = SecretSharing::Shamir::Container.new(512, 512)
      s1.n.must_equal(512)
      s1.k.must_equal(512)
    end

    it 'will raise if n > 512' do
      lambda { SecretSharing::Shamir::Container.new(513) }.must_raise(ArgumentError)
    end

    it 'must return the correct min shares constant value' do
      SecretSharing::Shamir::Container::MIN_SHARES.must_equal(2)
    end

    it 'must return the correct max shares constant value' do
      SecretSharing::Shamir::Container::MAX_SHARES.must_equal(512)
    end

  end # describe initialization

  describe 'creating a container and setting a secret' do

    before do
      @num_shares = 5
      @c = SecretSharing::Shamir::Container.new(@num_shares)
      @secret_num = OpenSSL::BN.new('1234567890')
      @c.secret = SecretSharing::Shamir::Secret.new(:secret => @secret_num)
    end

    it 'will return true from #secret?' do
      @c.secret?.must_equal(true)
    end

    it 'will not return a nil #secret' do
      @c.secret.wont_be_nil
    end

    it 'will not return a nil #shares' do
      @c.shares.wont_be_nil
    end

    it 'will return an Array of #shares' do
      @c.shares.must_be_instance_of(Array)
    end

    it 'will return an Array of #shares of the same length as initialized with' do
      @c.shares.size.must_equal(@num_shares)
    end

    it 'will return an Array of #shares each of the correct class' do
      @c.shares.each do |share|
        share.must_be_instance_of(SecretSharing::Shamir::Share)
      end
    end

    it 'must raise an exception if a secret is attempted to be set more than once' do
      lambda { @c.secret = SecretSharing::Shamir::Secret.new }.must_raise(ArgumentError)
    end

  end # creating a container and setting a secret

  describe 'generating shares when a secret is provided' do

    it 'should generate unique shares for the min number of shares and a tiny secret' do
      c1 = SecretSharing::Shamir::Container.new(2)
      c1.secret  = SecretSharing::Shamir::Secret.new(:secret => OpenSSL::BN.new('123'))
      shares = c1.shares
      shares.size.must_equal(2)
      uniq_shares = shares.uniq
      shares.must_equal(uniq_shares)
    end

    it 'should generate unique shares for the max number of shares and a tiny secret' do
      c1 = SecretSharing::Shamir::Container.new(512)
      c1.secret  = SecretSharing::Shamir::Secret.new(:secret => OpenSSL::BN.new('123'))
      shares = c1.shares
      shares.size.must_equal(512)
      uniq_shares = shares.uniq
      shares.must_equal(uniq_shares)
    end

    it 'should generate unique shares for the min number of shares and a large secret' do
      c1 = SecretSharing::Shamir::Container.new(2)
# FIXME : Major Perf Issue : If OpenSSL::BN::rand(512) is given with 4096 instead of 512 this takes FOREVER
      c1.secret  = SecretSharing::Shamir::Secret.new(:secret => OpenSSL::BN::rand(512))
      shares = c1.shares
      shares.size.must_equal(2)
      uniq_shares = shares.uniq
      shares.must_equal(uniq_shares)
    end

    it 'should generate unique shares for the max number of shares and a large secret' do
      c1 = SecretSharing::Shamir::Container.new(512)
# FIXME : Major Perf Issue : If OpenSSL::BN::rand(512) is given with 4096 instead of 512 this takes FOREVER
      c1.secret  = SecretSharing::Shamir::Secret.new(:secret => OpenSSL::BN::rand(512))
      shares = c1.shares
      shares.size.must_equal(512)
      uniq_shares = shares.uniq
      shares.must_equal(uniq_shares)
    end

  end

  describe 'recovering a secret from a container' do

    before do
      @c1 = SecretSharing::Shamir::Container.new(5)    # creator
      @c2 = SecretSharing::Shamir::Container.new(5)    # recipient

      @c3 = SecretSharing::Shamir::Container.new(5, 3) # creator
      @c4 = SecretSharing::Shamir::Container.new(5, 3) # recipient

      @bad = SecretSharing::Shamir::Container.new(5, 3) # a bad actor
    end

    describe 'with a mix of valid and invalid shares' do

      before do
        # set a secret on the 'creators'
        @c1.secret  = SecretSharing::Shamir::Secret.new
        @c3.secret  = SecretSharing::Shamir::Secret.new
        @bad.secret = SecretSharing::Shamir::Secret.new
      end

      it 'should be able to recover secret when k equals n and all k valid shares are provided as Shamir::Share objects' do
        @c2 << @c1.shares[0]
        @c2 << @c1.shares[1]
        @c2 << @c1.shares[2]
        @c2 << @c1.shares[3]

        # with the last remaining share missing
        @c2.secret?.must_equal(false)

        @c2 << @c1.shares[4]

        # with the final share provided
        @c2.secret?.must_equal(true)
        @c2.secret.must_equal(@c1.secret)
      end

      it 'should raise an ArgumentError if n + 1 shares are provided (more than were originally generated)' do
        @c2 << @c1.shares[0]
        @c2 << @c1.shares[1]
        @c2 << @c1.shares[2]
        @c2 << @c1.shares[3]
        @c2.secret?.must_equal(false)
        @c2 << @c1.shares[4]
        @c2.secret?.must_equal(true)

        lambda { @c2 << @bad.shares[0] }.must_raise(ArgumentError)
      end

      it 'should raise an ArgumentError when k equals n and k-1 valid shares and 1 invalid share are provided as Shamir::Share objects' do
        @c2 << @c1.shares[0]
        @c2 << @c1.shares[1]
        @c2 << @c1.shares[2]
        @c2 << @c1.shares[3]

        # with the last remaining share missing
        @c2.secret?.must_equal(false)

        # with a bad share
        lambda { @c2 << @bad.shares[0] }.must_raise(ArgumentError)
      end

      it 'should raise an ArgumentError if the final @secret generated does not have a valid_hmac?' do
        # mocha instance mock using handy 'any_instance'
        SecretSharing::Shamir::Secret.any_instance.stubs(:valid_hmac?).returns(false)
        @c2 << @c1.shares[0]
        @c2 << @c1.shares[1]
        @c2 << @c1.shares[2]
        @c2 << @c1.shares[3]
        lambda { @c2 << @c1.shares[4] }.must_raise(ArgumentError)
      end

    end

    describe 'with valid shares resulting from a random secret' do

      before do
        extend SecretSharing::Shamir
        # set a secret on both of the 'creators'
        @c1.secret = SecretSharing::Shamir::Secret.new
        @c3.secret = SecretSharing::Shamir::Secret.new
      end

      # This exposed a bug in the prime number generation; for instance 4*8
      # passes.
      it 'should be able to recover secret with a bitlength of 5*8' do
        secret = SecretSharing::Shamir::Secret.new(:secret => get_random_number(5*8))
        c = SecretSharing::Shamir::Container.new(4,2)
        c.secret = secret

        (0...4).to_a.permutation(2).collect{|e| e.sort}.uniq.each do |indexes|
          c2 = SecretSharing::Shamir::Container.new(2)
          indexes.each do |index|
            c2 << c.shares[index]
          end
          c2.secret?.must_equal(true)
          c2.secret.must_equal(c.secret)
        end
      end

      it 'should be able to recover secret when k equals n and all k shares are provided as Shamir::Share objects' do
        @c2 << @c1.shares[0]
        @c2 << @c1.shares[1]
        @c2 << @c1.shares[2]
        @c2 << @c1.shares[3]

        # with the last remaining share missing
        @c2.secret?.must_equal(false)

        @c2 << @c1.shares[4]

        # with the final share provided
        @c2.secret?.must_equal(true)
        @c2.secret.must_equal(@c1.secret)
      end

      it 'should be able to recover secret when k equals n and all k shares are provided as Shamir::Share objects converted to Strings' do
        @c2 << @c1.shares[0].to_s
        @c2 << @c1.shares[1].to_s
        @c2 << @c1.shares[2].to_s
        @c2 << @c1.shares[3].to_s

        # with the last remaining share missing
        @c2.secret?.must_equal(false)

        @c2 << @c1.shares[4].to_s

        # with the final share provided
        @c2.secret?.must_equal(true)
        @c2.secret.must_equal(@c1.secret)
      end

      it 'should be able to recover secret when k < n and minimum k shares are provided as Shamir::Share objects' do
        @c4 << @c3.shares[0]
        @c4 << @c3.shares[1]

        # with the last remaining share missing
        @c4.secret?.must_equal(false)

        @c4 << @c3.shares[2]

        # with the final share provided
        @c4.secret?.must_equal(true)
        @c4.secret.must_equal(@c3.secret)
      end

      it 'should be able to recover secret when k < n and minimum k shares are provided as Shamir::Share objects converted to Strings' do
        @c4 << @c3.shares[0].to_s
        @c4 << @c3.shares[1].to_s

        # with the last remaining share missing
        @c4.secret?.must_equal(false)

        @c4 << @c3.shares[2].to_s

        # with the final share provided
        @c4.secret?.must_equal(true)
        @c4.secret.must_equal(@c3.secret)
      end

      it 'should be able to recover secret when k < n and more than minimum k shares are provided as Shamir::Share objects converted to Strings' do
        @c4 << @c3.shares[0].to_s
        @c4 << @c3.shares[1].to_s

        # with the last remaining share missing
        @c4.secret?.must_equal(false)

        @c4 << @c3.shares[2].to_s

        # with the final needed share provided
        @c4.secret?.must_equal(true)
        @c4.secret.must_equal(@c3.secret)

        # with an extra valid share provided
        @c4 << @c3.shares[3].to_s
        @c4.secret?.must_equal(true)
        @c4.secret.must_equal(@c3.secret)
      end

    end

  end # recovering a secret from a container

end # describe SecretSharing::Shamir::Container
