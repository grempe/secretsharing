# -*- encoding: utf-8 -*-
require 'test/unit'

# Allow 'require_relative' to work in Ruby 1.8.x and 1.9.x (where
# 'require_relative' is the current method.
#
# tested w/ RVM installed MRI Ruby 1.8.7, 1.9.2, 1.9.3 using:
#   rvm 1.8.7,1.9.2,1.9.3 do rake test
#
# See : http://stackoverflow.com/questions/4333286/ruby-require-vs-require-relative-best-practice-to-workaround-running-in-both
#
unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end
require_relative '../lib/secretsharing'

DEFAULT_SECRET_BITLENGTH = 256

class TestShamir < Test::Unit::TestCase
	def test_instantiation
		assert_raise( ArgumentError ) { SecretSharing::Shamir.new }
		s1 = SecretSharing::Shamir.new(5)
		assert_equal(5, s1.n)
		assert_equal(5, s1.k)
		assert(! s1.secret_set?)
		s2 = SecretSharing::Shamir.new(5, 3)
		assert_equal(5, s2.n)
		assert_equal(3, s2.k)
		assert(! s2.secret_set?)
		assert_raise( ArgumentError ) { SecretSharing::Shamir.new(5, 7) }
		assert_raise( ArgumentError ) { SecretSharing::Shamir.new(1) }
	end

	def test_create_random_secret
		s = SecretSharing::Shamir.new(5)
		s.create_random_secret()
		assert(s.secret_set?)
		assert_not_nil(s.secret)
		assert_not_nil(s.shares)
		assert_equal(Array, s.shares.class)
		assert_equal(5, s.shares.length)
		assert_equal(SecretSharing::Shamir::Share, s.shares[0].class)
		assert_equal(DEFAULT_SECRET_BITLENGTH, s.secret_bitlength)

		# can only be called once
		assert_raise( RuntimeError) { s.create_random_secret() }

		s2 = SecretSharing::Shamir.new(7)
		s2.create_random_secret(512)
		assert_equal(512, s2.secret_bitlength)
	end

	def test_set_fixed_secret
		s = SecretSharing::Shamir.new(5)
		s.set_fixed_secret(OpenSSL::BN.new('12345678901234567890'))
		assert(s.secret_set?)
		assert_not_nil(s.secret)
		assert_not_nil(s.shares)
		assert_equal(Array, s.shares.class)
		assert_equal(5, s.shares.length)
		assert_equal(SecretSharing::Shamir::Share, s.shares[0].class)
		assert_equal(64, s.secret_bitlength)

		# can only be called once
		assert_raise( RuntimeError) { 
			s.set_fixed_secret(OpenSSL::BN.new('12345678901234567891')) }

		# test using string as parameter instead of OpenSSL::BN instance
		s2 = SecretSharing::Shamir.new(5)
		s2.set_fixed_secret('12345678901234567890')
		assert(s2.secret_set?)
		assert_not_nil(s2.secret)
		assert_not_nil(s2.shares)
		assert_equal(Array, s2.shares.class)
		assert_equal(5, s2.shares.length)
		assert_equal(SecretSharing::Shamir::Share, s2.shares[0].class)
		assert_equal(64, s2.secret_bitlength)
	end

	def test_recover_secret_k_eq_n
		s = SecretSharing::Shamir.new(5)
		s.create_random_secret()
		
		s2 = SecretSharing::Shamir.new(5)
		s2 << s.shares[0]
		assert(! s2.secret_set?)
		assert_nil(s2.secret)
		# adding the same share raises an error
		assert_raise( RuntimeError ) { s2 << s.shares[0] }
		# add more shares
		s2 << s.shares[1]
		assert(! s2.secret_set?)
		s2 << s.shares[2]
		assert(! s2.secret_set?)
		s2 << s.shares[3]
		assert(! s2.secret_set?)
		s2 << s.shares[4]
		assert(s2.secret_set?)
		assert_equal(s.secret, s2.secret)
	end

	def test_recover_secret_k_eq_n_fixed_secret
		s = SecretSharing::Shamir.new(5)
		secret = OpenSSL::BN.new('1234567890123456789012345678901234567890')

		s.set_fixed_secret(secret)
		
		s2 = SecretSharing::Shamir.new(5)
		s2 << s.shares[0]
		assert(! s2.secret_set?)
		assert_nil(s2.secret)
		# adding the same share raises an error
		assert_raise( RuntimeError ) { s2 << s.shares[0] }
		# add more shares
		s2 << s.shares[1]
		assert(! s2.secret_set?)
		s2 << s.shares[2]
		assert(! s2.secret_set?)
		s2 << s.shares[3]
		assert(! s2.secret_set?)
		s2 << s.shares[4]
		assert(s2.secret_set?)
		assert_equal(secret, s2.secret)
	end

	def test_recover_secret_k_eq_n_strings
		s = SecretSharing::Shamir.new(2)
		s.create_random_secret()

		s2 = SecretSharing::Shamir.new(2)
		s2 << s.shares[0].to_s
		s2 << s.shares[1].to_s

		assert_equal(s.secret, s2.secret)
	end

	def test_recover_secret_k_le_n
		s = SecretSharing::Shamir.new(5, 3)
		s.create_random_secret()
		
		s2 = SecretSharing::Shamir.new(5, 3)
		s2 << s.shares[0]
		assert(! s2.secret_set?)
		assert_nil(s2.secret)
		# add more shares
		s2 << s.shares[1]
		assert(! s2.secret_set?)
		s2 << s.shares[2]
		assert(s2.secret_set?)
		assert_equal(s.secret, s2.secret)

		# adding more shares than needed raises an error
		assert_raise( RuntimeError ) { s2 << s.shares[3] }
	end	

	def test_recover_secret_k_le_n_strings
		s = SecretSharing::Shamir.new(5, 3)
		s.create_random_secret()
		
		s2 = SecretSharing::Shamir.new(5, 3)
		s2 << "#{s.shares[0]}"
		assert(! s2.secret_set?)
		assert_nil(s2.secret)
		# add more shares
		s2 << "#{s.shares[1]}"
		assert(! s2.secret_set?)
		s2 << s.shares[2].to_s
		assert(s2.secret_set?)
		assert_equal(s.secret, s2.secret)

		# adding more shares than needed raises an error
		assert_raise( RuntimeError ) { s2 << s.shares[3] }
	end	
end
