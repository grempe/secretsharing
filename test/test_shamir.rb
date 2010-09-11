require 'test/unit'
require 'lib/secretsharing/shamir'

DEFAULT_SECRET_BITLENGTH = 128

class TestShamir < Test::Unit::TestCase
	def test_instantiation
		assert_raise( ArgumentError ) { SecretSharing::Shamir.new }
		s1 = SecretSharing::Shamir.new(5)
		assert_equal(s1.n, 5)
		assert_equal(s1.k, 5)
		assert(! s1.secret_set?)
		s2 = SecretSharing::Shamir.new(5, 3)
		assert_equal(s2.n, 5)
		assert_equal(s2.k, 3)
		assert(! s2.secret_set?)
		assert_raise( ArgumentError ) { SecretSharing::Shamir.new(5, 7) }
	end

	def test_create_random_secret
		s = SecretSharing::Shamir.new(5)
		s.create_random_secret()
		assert(s.secret_set?)
		assert_not_nil(s.secret)
		assert_not_nil(s.shares)
		assert_equal(s.shares.class, Array)
		assert_equal(s.shares.length, 5)
		assert_equal(s.shares[0].class, SecretSharing::Shamir::Share)
		assert_equal(s.secret_bitlength, DEFAULT_SECRET_BITLENGTH)

		# can only be called once
		assert_raise( RuntimeError) { s.create_random_secret() }

		s2 = SecretSharing::Shamir.new(7)
		s2.create_random_secret(256)
		assert_equal(s2.secret_bitlength, 256)
	end

	def test_recover_secret_k_eq_n
		s = SecretSharing::Shamir.new(5)
		s.create_random_secret()
		
		s2 = SecretSharing::Shamir.new(5)
		s2.shares << s.shares[0]
		assert_equal(s2.shares.length, 1)
		assert(! s2.secret_set?)
		assert_nil(s2.secret)
		# adding the same share raises an error
		assert_raise( RuntimeError ) { s2.shares << s.shares[0] }
		# add more shares
		s2.shares << s.shares[1]
		assert(! s2.secret_set?)
		s2.shares << s.shares[2]
		assert(! s2.secret_set?)
		s2.shares << s.shares[3]
		assert(! s2.secret_set?)
		s2.shares << s.shares[4]
		assert(s2.secret_set?)
		assert_equal(s.secret, s2.secret)
	end

	def test_recover_secret_k_le_n
		s = SecretSharing::Shamir.new(5, 3)
		s.create_random_secret()
		
		s2 = SecretSharing::Shamir.new(5, 3)
		s2.shares << s.shares[0]
		assert_equal(s2.shares.length, 1)
		assert(! s2.secret_set?)
		assert_nil(s2.secret)
		# add more shares
		s2.shares << s.shares[1]
		assert(! s2.secret_set?)
		s2.shares << s.shares[2]
		assert(s2.secret_set?)
		assert_equal(s.secret, s2.secret)

		# adding more shares than needed raises an error
		assert_raise( RuntimeError ) { s2.shares << s.shares[3] }
	end	
end
