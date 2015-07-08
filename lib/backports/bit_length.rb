# Backport support for Bignum#bit_length and Fixnum#bit_length which were added in Ruby 2.1
# See : http://globaldev.co.uk/2014/05/ruby-2-1-in-detail/
# See : https://github.com/marcandre/backports
#
# NOTE: Had to add this as a monkey patch here since Bignum#bit_length is broken
# in the backports gem. Bug filed:
# https://github.com/marcandre/backports/issues/95

# Supports #bit_length
# a direct copy from backports gem
unless Range.method_defined? :bsearch
  class Range
    def bsearch
      return to_enum(:bsearch) unless block_given?
      from = self.begin
      to   = self.end
      unless from.is_a?(Numeric) && to.is_a?(Numeric)
        raise TypeError, "can't do binary search for #{from.class}"
      end

      midpoint = nil
      if from.is_a?(Integer) && to.is_a?(Integer)
        convert = Proc.new{ midpoint }
      else
        map = Proc.new do |pk, unpk, nb|
          result, = [nb.abs].pack(pk).unpack(unpk)
          nb < 0 ? -result : result
        end
        from = map['D', 'q', to.to_f]
        to   = map['D', 'q', to.to_f]
        convert = Proc.new{ map['q', 'D', midpoint] }
      end
      to -= 1 if exclude_end?
      satisfied = nil
      while from <= to do
        midpoint = (from + to).div(2)
        result = yield(cur = convert.call)
        case result
        when Numeric
          return cur if result == 0
          result = result < 0
        when true
          satisfied = cur
        when nil, false
          # nothing to do
        else
          raise TypeError, "wrong argument type #{result.class} (must be numeric, true, false or nil)"
        end

        if result
          to = midpoint - 1
        else
          from = midpoint + 1
        end
      end
      satisfied
    end
  end
end

# For MRI < 2.1, and other Rubies
# A direct copy from backports gem
unless Fixnum.method_defined? :bit_length
  # require 'backports/2.0.0/range/bsearch'
  class Fixnum
    def bit_length
      n = if self >= 0
        self + 1
      else
        -self
      end
      (0...8 * size).bsearch{|i| n <= (1 << i) }
    end
  end
end

# For MRI < 2.1, and other Rubies
# My own temporary implementation of bit_length. Until the bug report
# above is resolved.
unless Bignum.method_defined? :bit_length
  class Bignum
    def bit_length
      (self).abs.to_s(2).length
    end
  end
end
