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

require File.expand_path("../spec_helper", __FILE__)

describe SecretSharing::Shamir do

  describe "initialization" do

    it "will raise when instantiated with no args" do
      lambda { SecretSharing::Shamir.new }.must_raise(ArgumentError)
    end

    it "will create shares with n and k equal when given one Integer arg" do
      s1 = SecretSharing::Shamir.new(5)
      s1.n.must_equal(5)
      s1.k.must_equal(5)
    end

    it "will create shares with n and k set to their own values when given two Integer args" do
      s1 = SecretSharing::Shamir.new(5, 3)
      s1.n.must_equal(5)
      s1.k.must_equal(3)
    end

    it "will create shares with n and k equal when given one Integer as String arg" do
      s1 = SecretSharing::Shamir.new("5")
      s1.n.must_equal(5)
      s1.k.must_equal(5)
    end

    it "will raise an exception with n being a non-Integer String arg" do
      lambda{SecretSharing::Shamir.new("foo")}.must_raise(ArgumentError)
    end

    it "will create shares with n and k set to their own values when given two Integer as String args" do
      s1 = SecretSharing::Shamir.new("5", "3")
      s1.n.must_equal(5)
      s1.k.must_equal(3)
    end

    it "will return false when secret_set? is called after initialization with only n arg set" do
      s1 = SecretSharing::Shamir.new(5)
      s1.secret_set?.must_equal(false)
    end

    it "will return false when secret_set? is called after initialization with n and k arg set" do
      s1 = SecretSharing::Shamir.new(5, 3)
      s1.secret_set?.must_equal(false)
    end

    it "will return nil secret when called after initialization with only n arg set" do
      s1 = SecretSharing::Shamir.new(5)
      s1.secret.must_be_nil
    end

    it "will return nil secret when called after initialization with n and k arg set" do
      s1 = SecretSharing::Shamir.new(5, 3)
      s1.secret.must_be_nil
    end

    it "will raise if k > n" do
      lambda { SecretSharing::Shamir.new(5, 6) }.must_raise(ArgumentError)
    end

    it "will raise if only n is provided and it is < 2" do
      lambda { SecretSharing::Shamir.new(1) }.must_raise(ArgumentError)
    end

    it "will raise unless k >= 2" do
      lambda { SecretSharing::Shamir.new(1, 1) }.must_raise(ArgumentError)
    end

    it "will initialize if both k and n are at max size of 512" do
      s1 = SecretSharing::Shamir.new(512, 512)
      s1.n.must_equal(512)
      s1.k.must_equal(512)
    end

    it "will raise if n > 512" do
      lambda { SecretSharing::Shamir.new(513) }.must_raise(ArgumentError)
    end

  end # describe initialization

  describe "creating random secret with default args" do

    before do
      @num_shares = 5
      @s = SecretSharing::Shamir.new(@num_shares)
      @s.create_random_secret
    end

    it "will return true from #secret_set?" do
      @s.secret_set?.must_equal(true)
    end

    it "will not return a nil secret" do
      @s.secret.wont_be_nil
    end

    it "will not return a nil shares" do
      @s.shares.wont_be_nil
    end

    it "will return an Array of shares" do
      @s.shares.must_be_instance_of(Array)
    end

    it "will return an Array of shares of the same length as initialized with" do
      @s.shares.size.must_equal(@num_shares)
    end

    it "must return share instances of the correct class" do
      @s.shares.each do |share|
        share.must_be_instance_of(SecretSharing::Shamir::Share)
      end
    end

    it "must return the correct min secret bitlength constant value" do
      SecretSharing::Shamir::MIN_SECRET_BITLENGTH.must_equal(1)
    end

    it "must return the correct default secret bitlength constant value" do
      SecretSharing::Shamir::DEFAULT_SECRET_BITLENGTH.must_equal(256)
    end

    it "must return the correct max secret bitlength constant value" do
      SecretSharing::Shamir::MAX_SECRET_BITLENGTH.must_equal(4096)
    end

    it "must return the correct min shares constant value" do
      SecretSharing::Shamir::MIN_SHARES.must_equal(2)
    end

    it "must return the correct max shares constant value" do
      SecretSharing::Shamir::MAX_SHARES.must_equal(512)
    end

    it "must return the correct secret_bitlength when initialized with the defaults" do
      @s.secret_bitlength.must_equal(SecretSharing::Shamir::DEFAULT_SECRET_BITLENGTH)
    end

    it "must raise an exception if #create_random_secret is called more than once" do
      lambda {@s.create_random_secret}.must_raise(RuntimeError)
    end

  end # describe creating random secret

  describe "creating random secret with custom args" do

    it "must set secret_bitlength to the same length the random secret was created with" do
      @s = SecretSharing::Shamir.new(5)
      @s.create_random_secret(1024)
      @s.secret_bitlength.must_equal(1024)
    end

    it "must raise an exception if passed a bit length greater than 4096" do
      @s = SecretSharing::Shamir.new(5)
      lambda{ @s.create_random_secret(4097)}.must_raise(ArgumentError)
    end

    it "must raise an exception if passed a non-integer arg" do
      @s = SecretSharing::Shamir.new(5)
      lambda{ @s.create_random_secret('a')}.must_raise(ArgumentError)
    end

  end

  describe "creating a fixed secret with an OpenSSL::BN" do

    before do
      @num_shares = 5
      @bn = OpenSSL::BN.new('12345678901234567890')
      @s = SecretSharing::Shamir.new(@num_shares)
      @s.set_fixed_secret(@bn)
    end

    it "should not allow fixed secret to be set twice" do
      lambda{ @s.set_fixed_secret(@bn) }.must_raise(RuntimeError)
    end

    it "should allow fixed secret to be set with num_bits == 1" do
      @s = SecretSharing::Shamir.new(@num_shares)
      bn = OpenSSL::BN.new("1") # => 1 num_bits
      bn.num_bits.must_equal(1)
      @s.set_fixed_secret(bn)
      @s.secret_bitlength.must_equal(1)
    end

    it "should allow fixed secret to be set with num_bits == 1024" do
      @s = SecretSharing::Shamir.new(@num_shares)
      bn = OpenSSL::BN.new("#{'1234567890' * 30 + '123456789'}") # => 1024 num_bits
      bn.num_bits.must_equal(1024)
      @s.set_fixed_secret(bn)
      @s.secret_bitlength.must_equal(1024)
    end

    it "should not allow fixed secret to be set with num_bits < 1" do
      @s = SecretSharing::Shamir.new(@num_shares)
      bn = OpenSSL::BN.new("0") # => o num_bits
      bn.num_bits.must_equal(0)
      lambda{ @s.set_fixed_secret(bn) }.must_raise(RuntimeError)
    end

    it "should not allow fixed secret to be set with num_bits > 4097" do
      @s = SecretSharing::Shamir.new(@num_shares)
      bn = OpenSSL::BN.new("#{'1234567890' * 131}") # => 4349 num_bits
      bn.num_bits.must_equal(4349)
      lambda{ @s.set_fixed_secret(bn) }.must_raise(RuntimeError)
    end

    it "should return true when #secret_set? is called" do
      @s.secret_set?.must_equal(true)
    end

    it "should return a secret password" do
      @s.secret_password.wont_be_nil
    end

    it "should not return nil when #secret is called" do
      @s.secret.wont_be_nil
    end

    it "should not return nil when #shares is called" do
      @s.shares.wont_be_nil
    end

    it "should return an Array of shares" do
      @s.shares.must_be_instance_of(Array)
    end

    it "should return the appropriate number of shares" do
      @s.shares.size.must_equal(@num_shares)
    end

    it "should return shares of the appropriate class" do
      @s.shares.each do |share|
        share.must_be_instance_of(SecretSharing::Shamir::Share)
      end
    end

    it "should return a secret bitlength that is appropriate" do
      @s.secret_bitlength.must_equal(64)
    end

  end

  describe "creating a fixed secret with a String" do

    before do
      @num_shares = 5
      @bn = '12345678901234567890'
      @s = SecretSharing::Shamir.new(@num_shares)
      @s.set_fixed_secret(@bn)
    end

    it "should not allow fixed secret to be set twice" do
      lambda{ @s.set_fixed_secret(@bn) }.must_raise(RuntimeError)
    end

    it "should allow fixed secret to be set with num_bits == 1" do
      @s = SecretSharing::Shamir.new(@num_shares)
      bn = OpenSSL::BN.new("1") # => 1 num_bits
      bn.num_bits.must_equal(1)
      @s.set_fixed_secret(bn.to_s)
      @s.secret_bitlength.must_equal(1)
    end

    it "should allow fixed secret to be set with num_bits == 1024" do
      @s = SecretSharing::Shamir.new(@num_shares)
      bn = OpenSSL::BN.new("#{'1234567890' * 30 + '123456789'}") # => 1024 num_bits
      bn.num_bits.must_equal(1024)
      @s.set_fixed_secret(bn.to_s)
      @s.secret_bitlength.must_equal(1024)
    end

    it "should not allow fixed secret to be set with num_bits < 1" do
      @s = SecretSharing::Shamir.new(@num_shares)
      bn = OpenSSL::BN.new("0") # => o num_bits
      bn.num_bits.must_equal(0)
      lambda{ @s.set_fixed_secret(bn.to_s) }.must_raise(RuntimeError)
    end

    it "should not allow fixed secret to be set with num_bits > 4096" do
      @s = SecretSharing::Shamir.new(@num_shares)
      bn = OpenSSL::BN.new("#{'1234567890' * 131}") # => 4349 num_bits
      bn.num_bits.must_equal(4349)
      lambda{ @s.set_fixed_secret(bn.to_s) }.must_raise(RuntimeError)
    end

    it "should return true when #secret_set? is called" do
      @s.secret_set?.must_equal(true)
    end

    it "should return a secret password" do
      @s.secret_password.wont_be_nil
    end

    it "should not return nil when #secret is called" do
      @s.secret.wont_be_nil
    end

    it "should not return nil when #shares is called" do
      @s.shares.wont_be_nil
    end

    it "should return an Array of shares" do
      @s.shares.must_be_instance_of(Array)
    end

    it "should return the appropriate number of shares" do
      @s.shares.size.must_equal(@num_shares)
    end

    it "should return shares of the appropriate class" do
      @s.shares.each do |share|
        share.must_be_instance_of(SecretSharing::Shamir::Share)
      end
    end

    it "should return a secret bitlength that is appropriate" do
      @s.secret_bitlength.must_equal(64)
    end

  end

  describe "recovering a secret" do

    before do
      @s1 = SecretSharing::Shamir.new(5)    # creator
      @s2 = SecretSharing::Shamir.new(5)    # recipient

      @s3 = SecretSharing::Shamir.new(5, 3) # creator
      @s4 = SecretSharing::Shamir.new(5, 3) # recipient
    end

    describe "with invalid shares" do

      it "should raise an exception when passed a simple Integer" do
        lambda{ @s2 << 1 }.must_raise(ArgumentError)
      end

      it "should raise an exception when passed a simple String that is not of the expected format" do
        lambda{ @s2 << "a" }.must_raise(ArgumentError)
      end

    end

    describe "with valid shares resulting from a random secret" do

      before do
        # set a secret on both of the 'creators'
        @s1.create_random_secret
        @s3.create_random_secret
      end

      it "should raise an exception if one of the shares is provided twice" do
        @s2 << @s1.shares[0]
        lambda{ @s2 << @s1.shares[0] }.must_raise(RuntimeError)
      end

      it "should be able to recover secret when k equals n and all k shares are provided as Shamir::Share objects" do
        @s2 << @s1.shares[0]
        @s2 << @s1.shares[1]
        @s2 << @s1.shares[2]
        @s2 << @s1.shares[3]

        # with the last remaining share missing
        @s2.secret_set?.must_equal(false)

        @s2 << @s1.shares[4]

        # with the final share provided
        @s2.secret_set?.must_equal(true)
        @s2.secret.must_equal(@s1.secret)
      end

      it "should be able to recover secret when k equals n and all k shares are provided as Shamir::Share objects converted to Strings" do
        @s2 << @s1.shares[0].to_s
        @s2 << @s1.shares[1].to_s
        @s2 << @s1.shares[2].to_s
        @s2 << @s1.shares[3].to_s

        # with the last remaining share missing
        @s2.secret_set?.must_equal(false)

        @s2 << @s1.shares[4]

        # with the final share provided
        @s2.secret_set?.must_equal(true)
        @s2.secret.must_equal(@s1.secret)
      end

      it "should be able to recover secret when k < n and minimum k shares are provided as Shamir::Share objects" do
        @s4 << @s3.shares[0]
        @s4 << @s3.shares[1]

        # with the last remaining share missing
        @s4.secret_set?.must_equal(false)

        @s4 << @s3.shares[2]

        # with the final share provided
        @s4.secret_set?.must_equal(true)
        @s4.secret.must_equal(@s3.secret)
      end

      it "should be able to recover secret when k < n and minimum k shares are provided as Shamir::Share objects converted to Strings" do
        @s4 << @s3.shares[0].to_s
        @s4 << @s3.shares[1].to_s

        # with the last remaining share missing
        @s4.secret_set?.must_equal(false)

        @s4 << @s3.shares[2].to_s

        # with the final share provided
        @s4.secret_set?.must_equal(true)
        @s4.secret.must_equal(@s3.secret)
      end

      it "should be raise exception when k < n and one too many shares are provided" do
        @s4 << @s3.shares[0]
        @s4 << @s3.shares[1]
        @s4 << @s3.shares[2]
        @s4.secret_set?.must_equal(true)
        @s4.secret.must_equal(@s3.secret)

        lambda{ @s4 << @s3.shares[3] }.must_raise(RuntimeError)
      end

    end

    describe "with valid shares resulting from an OpenSSL:BN secret" do

      before do
        secret = OpenSSL::BN.new('1234567890123456789012345678901234567890')
        @s1.set_fixed_secret(secret)
        @s3.set_fixed_secret(secret)
      end

      it "should raise an exception if one of the shares is provided twice" do
        @s2 << @s1.shares[0]
        lambda{ @s2 << @s1.shares[0] }.must_raise(RuntimeError)
      end

      it "should be able to recover secret when k equals n and all k shares are provided" do
        @s2 << @s1.shares[0]
        @s2 << @s1.shares[1]
        @s2 << @s1.shares[2]
        @s2 << @s1.shares[3]

        # with the last remaining share missing
        @s2.secret_set?.must_equal(false)

        @s2 << @s1.shares[4]

        # with the final share provided
        @s2.secret_set?.must_equal(true)
        @s2.secret.must_equal(@s1.secret)
      end

      it "should be able to recover secret when k < n and minimum k shares are provided as Shamir::Share objects" do
        @s4 << @s3.shares[0]
        @s4 << @s3.shares[1]

        # with the last remaining share missing
        @s4.secret_set?.must_equal(false)

        @s4 << @s3.shares[2]

        # with the final share provided
        @s4.secret_set?.must_equal(true)
        @s4.secret.must_equal(@s3.secret)
      end

      it "should be able to recover secret when k < n and minimum k shares are provided as Shamir::Share objects converted to Strings" do
        @s4 << @s3.shares[0].to_s
        @s4 << @s3.shares[1].to_s

        # with the last remaining share missing
        @s4.secret_set?.must_equal(false)

        @s4 << @s3.shares[2].to_s

        # with the final share provided
        @s4.secret_set?.must_equal(true)
        @s4.secret.must_equal(@s3.secret)
      end

      it "should be raise exception when k < n and one too many shares are provided" do
        @s4 << @s3.shares[0]
        @s4 << @s3.shares[1]
        @s4 << @s3.shares[2]
        @s4.secret_set?.must_equal(true)
        @s4.secret.must_equal(@s3.secret)

        lambda{ @s4 << @s3.shares[3] }.must_raise(RuntimeError)
      end

    end

  end

end
