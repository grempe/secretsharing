module SecretSharing

  # A SecretSharing::Shamir::Share object represents a share in the
  # Shamir secret sharing scheme. The share consists of a point (x,y) on
  # a polynomial over Z/Zp, where p is a prime.
  class Shamir::Share

    attr_reader :x, :y, :prime_bitlength, :prime

    FORMAT_VERSION = '0'

    # Create a new share with the given point, prime and prime bitlength.
    def initialize(x, y, prime, prime_bitlength)
      @x               = x
      @y               = y
      @prime           = prime
      @prime_bitlength = prime_bitlength
    end

    # Create a new share from a string format representation. For
    # a discussion of the format, see the to_s() method.
    def self.from_string(string)
      x                = string[1,2].hex
      prime_bitlength  = 4 * string[-2,2].hex + 1
      p_x_str          = string[3, string.length - 9]
      checksum         = string[-6, 4]

      self.validate_share_format(string)
      self.validate_checksum(checksum, p_x_str)

      prime = SecretSharing::Shamir.smallest_prime_of_bitlength(prime_bitlength)

      self.new(x, OpenSSL::BN.new(p_x_str, 16), prime, prime_bitlength)
    end

    # A string representation of the share, that can for example be
    # distributed in printed form.
    # The string is an uppercase hexadecimal string of the following
    # format: ABBC*DDDDEEEE, where
    # * A (the first nibble) is the version number of the format, currently
    #   fixed to 0.
    # * B (the next byte, two hex characters) is the x coordinate of the
    #   point on the polynomial.
    # * C (the next variable length of bytes) is the y coordinate of the
    #   point on the polynomial.
    # * D (the next two bytes, four hex characters) is the two highest
    #   bytes of the SHA1 hash on the string representing the y coordinate,
    #   it is used as a checksum to guard against typos
    # * E (the next two bytes, four hex characters) is the bitlength of the
    #   prime number in nibbles.
    def to_s
      # bitlength in nibbles to save space
      prime_nibbles = (@prime_bitlength - 1) / 4
      p_x = ("%x" % @y).upcase
      FORMAT_VERSION + ("%02x" % @x).upcase \
        + p_x \
        + Digest::SHA1.hexdigest(p_x)[0,4].upcase \
        + ("%02x" % prime_nibbles).upcase
    end

    # Shares are equal if their string representation is the same.
    def ==(share)
      share.to_s == self.to_s
    end

    # FIXME : should not be a Class method.
    def self.validate_share_format(share_string)
      version = share_string[0,1]
      raise "Invalid share format version # '#{version}', expected '0'" if version != '0'
    end

    # FIXME : should not be a Class method.
    def self.validate_checksum(checksum, p_x_str)
      computed_checksum = Digest::SHA1.hexdigest(p_x_str)[0,4].upcase
      if checksum != computed_checksum
        raise "Invalid checksum. Expected #{computed_checksum}, got #{checksum}"
      end
    end

  end # class

end # module

