# -*- encoding: utf-8 -*-
require File.expand_path("../spec_helper", __FILE__)


describe SecretSharing::Shamir::Share do

  describe "initialization" do

    it "will raise when instantiated with no args" do
      lambda { SecretSharing::Shamir::Share.new }.must_raise(ArgumentError)
    end

    it "will raise when instantiated with missing args" do
      lambda { SecretSharing::Shamir::Share.new(1, 1, 1) }.must_raise(ArgumentError)
      lambda { SecretSharing::Shamir::Share.new(1, 1) }.must_raise(ArgumentError)
      lambda { SecretSharing::Shamir::Share.new(1) }.must_raise(ArgumentError)
    end

    it "will be instantiated when provided with complete args" do
      @s = SecretSharing::Shamir::Share.new(1, 1, 1, 1)
    end

    it "will be instantiated from a valid String provided to the Share#from_string method" do
      @s = SecretSharing::Shamir::Share.from_string("0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341")
    end

    it "will raise when an otherwise valid String is provided with the VERSION part of the string changed from 0 to 1" do
      @s = SecretSharing::Shamir::Share.from_string("0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341")
      @s.must_be_kind_of(SecretSharing::Shamir::Share)
      lambda{ @s = SecretSharing::Shamir::Share.from_string("1016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341") }.must_raise(RuntimeError)
    end

    it "will raise when an otherwise valid String is provided with the CHECKSUM part of the string changed modified" do
      @s = SecretSharing::Shamir::Share.from_string("0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341")
      @s.must_be_kind_of(SecretSharing::Shamir::Share)
      skip("Which part of the string needs to change?")
      lambda{ @s = SecretSharing::Shamir::Share.from_string("0016C984F871AA524431793D2F0BB86319D870BEAF3FE106CEAF262E826DCB3FD1A0B81341") }.must_raise(RuntimeError)
    end

    it "will be instantiated from a to_s String provided to the Share#from_string method" do
      @s = SecretSharing::Shamir::Share.new(1, 1, 1, 1)
      share = @s.to_s
      @s = SecretSharing::Shamir::Share.from_string(share)
    end

    it "must be able to be compared directly to another share (==)" do
      @s1 = SecretSharing::Shamir::Share.new(1, 1, 1, 1)
      @s2 = SecretSharing::Shamir::Share.new(1, 1, 1, 1)

      @s1.must_equal(@s2)
    end

  end

end
