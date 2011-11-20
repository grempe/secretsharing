require 'openssl'
require 'digest/sha1'
require 'base64'

module SecretSharing

  # The SecretSharing::Shamir class can be used to share random
  # secrets between n people, so that k < n people can recover the
  # secret, but k-1 people learn nothing (in an information-theoretical
  # sense) about the secret.
  #
  # For a theoretical background, see:
  #   http://www.cs.tau.ac.il/~bchor/Shamir.html
  #   http://en.wikipedia.org/wiki/Secret_sharing#Shamir.27s_scheme
  #
  # To share a secret, create a new SecretSharing::Shamir object and
  # then call the create_random_secret() method. The secret is now in
  # the secret attribute and the shares are an array in the shares attribute.
  #
  # Alternatively, you can call the set_fixed_secret() method with an
  # OpenSSL::BN object (or something that can be passed to OpenSSL::BN.new)
  # to set your own secret.
  #
  # To recover a secret, create a SecretSharing::Shamir object and
  # add the necessary shares to it using the '<<' method. Once enough
  # shares have been added, the secret can be recovered in the secret
  # attribute.
  #
  class Shamir

    attr_reader :n, :k, :secret, :secret_bitlength, :shares

    MIN_SECRET_BITLENGTH     = 1
    DEFAULT_SECRET_BITLENGTH = 256
    MAX_SECRET_BITLENGTH     = 4096

    MIN_SHARES               = 2
    MAX_SHARES               = 512

    # To create a new SecretSharing::Shamir object, you can
    # pass either just n, or n and k where:
    #
    #   n = The total number of shares that will be created.
    #   k = The threshold number of the total shares needed to
    #       recreate the original secret. (Default = n)
    #
    # For example:
    #
    #   # 3(k) out of 5(n) shares needed to recover secret
    #   s = SecretSharing::Shamir.new(5, 3)
    #
    #   # 3(k) out of 3(n) shares needed to recover secret
    #   s = SecretSharing::Shamir.new(3)
    #
    def initialize(n, k = n)

      @n               = n.to_i
      @k               = k.to_i

      raise ArgumentError, "n must be an Integer" unless @n.is_a?(Integer)
      raise ArgumentError, "k must be an Integer" unless @k.is_a?(Integer)

      raise ArgumentError, "k must be <= n"              unless @k <= @n
      raise ArgumentError, "k must be >= #{MIN_SHARES}"  unless @k >= MIN_SHARES
      raise ArgumentError, "n must be <= #{MAX_SHARES}"  unless @n <= MAX_SHARES

      @secret          = nil
      @shares          = []
      @received_shares = []
    end

    # Check whether the secret is set.
    def secret_set?
      !@secret.nil?
    end

    # Create a random secret of a certain bitlength. Returns the
    # secret and stores it in the 'secret' attribute.
    def create_random_secret(bitlength = DEFAULT_SECRET_BITLENGTH)
      raise 'a secret has already been set' if secret_set?
      raise ArgumentError, "min bitlength is #{MIN_SECRET_BITLENGTH}" if bitlength < MIN_SECRET_BITLENGTH
      raise ArgumentError, "max bitlength is #{MAX_SECRET_BITLENGTH}" if bitlength > MAX_SECRET_BITLENGTH

      @secret = get_random_number(bitlength)
      @secret_bitlength = bitlength
      create_shares
      @secret
    end

    # Set the secret to a fixed OpenSSL::BN value. Stores it
    # in the 'secret' attribute, creates the corresponding shares and
    # returns the secret
    def set_fixed_secret(secret)
      raise 'a secret has already been set' if secret_set?

      secret = OpenSSL::BN.new(secret) unless secret.is_a?(OpenSSL::BN)
      raise "the bitlength of the fixed secret provided is #{secret.num_bits}, the min bitlength allowed is #{MIN_SECRET_BITLENGTH}" if secret.num_bits < MIN_SECRET_BITLENGTH
      raise "the bitlength of the fixed secret provided is #{secret.num_bits}, the max bitlength allowed is #{MAX_SECRET_BITLENGTH}" if secret.num_bits > MAX_SECRET_BITLENGTH

      @secret = secret
      @secret_bitlength = secret.num_bits
      create_shares
      @secret
    end

    # The secret in a password representation (Base64-encoded)
    def secret_password
      raise "Secret not (yet) set." unless secret_set?
      Base64.encode64([@secret.to_s(16)].pack('h*')).split("\n").join
    end

    # Add a secret share to the object. Accepts either a
    # SecretSharing::Shamir::Share instance or a string representing one.
    # Returns true if enough shares have been added to recover the secret,
    # false otherweise.
    def <<(share)
      unless share.is_a?(SecretSharing::Shamir::Share)
        if share.is_a?(String)
          share = SecretSharing::Shamir::Share.new(share)
        else
          raise ArgumentError, 'Expected SecretSharing::Shamir::Share or String'
        end
      end

      raise 'share has already been added' if @received_shares.include? share
      raise 'we already have enough shares, no need to add more' if @received_shares.length == @k

      @received_shares << share

      if @received_shares.length == @k
        recover_secret
        return true
      end
      false
    end

    # Computes the smallest prime of a given bitlength. Uses prime_fasttest
    # from the OpenSSL library with 20 attempts to be compatible to openssl
    # prime, which is used in the OpenXPKI::Crypto::Secret::Split library.
    def self.smallest_prime_of_bitlength(bitlength)
      # start with 2^bit_length + 1
      test_prime = OpenSSL::BN.new((2**bitlength + 1).to_s)
      prime_found = false
      while (!prime_found) do
        # prime_fasttest? 20 do be compatible to
        # openssl prime, which is used in
        # OpenXPKI::Crypto::Secret::Split
        prime_found = test_prime.prime_fasttest? 20
        test_prime += 2
      end
      test_prime
    end

    private

      # Creates a random number of a certain bitlength, optionally ensuring
      # the bitlength by setting the highest bit to 1.
      def get_random_number(bitlength, highest_bit_one = true)
        byte_length = (bitlength / 8.0).ceil
        rand_hex = OpenSSL::Random.random_bytes(byte_length).each_byte. \
                                 to_a.map { |a| "%02x" % a }.join('')

        rand = OpenSSL::BN.new(rand_hex, 16)

        begin
          rand.mask_bits!(bitlength)
        rescue OpenSSL::BNError
          # never mind if there was an error, this just means
          # rand was already smaller than 2^bitlength - 1
        end

        rand.set_bit!(bitlength) if highest_bit_one
        rand
      end

      # Creates the shares by computing random coefficients for a polynomial
      # and then computing points on this polynomial.
      def create_shares
        @coefficients = []
        @coefficients[0] = @secret

        # round up to next nibble
        next_nibble_bitlength = @secret_bitlength + \
                              (4 - (@secret_bitlength % 4))
        prime_bitlength = next_nibble_bitlength + 1
        @prime = self.class.smallest_prime_of_bitlength(prime_bitlength)

        # compute random coefficients
        (1..k-1).each do |x|
          @coefficients[x] = get_random_number(@secret_bitlength)
        end

        (1..n).each do |x|
          @shares[x-1] = construct_share(x, prime_bitlength)
        end
      end

      # Construct a share by evaluating the polynomial at x and creating
      # a SecretSharing::Shamir::Share object.
      def construct_share(x, bitlength)
        p_x = evaluate_polynomial_at(x)
        SecretSharing::Shamir::Share.new(x, p_x, @prime, bitlength)
      end

      # Evaluate the polynomial at x.
      def evaluate_polynomial_at(x)
        result = OpenSSL::BN.new('0')
        @coefficients.each_with_index do |coeff, i|
          result += coeff * OpenSSL::BN.new(x.to_s)**i
          result %= @prime
        end
        result
      end

      # Recover the secret by doing Lagrange interpolation.
      def recover_secret
        @secret = OpenSSL::BN.new('0')
        @received_shares.each do |share|
          l_x = l(share.x, @received_shares)
          summand = share.y * l_x
          summand %= share.prime
          @secret += summand
          @secret %= share.prime
        end
        @secret
      end

      # Part of the Lagrange interpolation.
      # This is l_j(0), i.e.
      # \prod_{x_j \neq x_i} \frac{-x_i}{x_j - x_i}
      # for more information compare Wikipedia:
      # http://en.wikipedia.org/wiki/Lagrange_form
      def l(x, shares)
        (shares.select { |s| s.x != x }.map do |s|
          minus_xi = OpenSSL::BN.new((-s.x).to_s)
          one_over_xj_minus_xi = OpenSSL::BN.new((x - s.x).to_s) \
                                 .mod_inverse(shares[0].prime)
          minus_xi.mod_mul(one_over_xj_minus_xi, shares[0].prime)
        end.inject { |p, f| p.mod_mul(f, shares[0].prime) })
      end

  end

end

