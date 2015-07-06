# -*- encoding: utf-8 -*-

# Copyright 2011-2015 Glenn Rempe

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

describe SecretSharing::Shamir do
  include SecretSharing::Shamir

  describe 'get_random_number' do
    it 'will return a Bignum' do
      r = get_random_number(32)
      r.class.must_equal(Bignum)
    end

    it 'will return a Bignum with a size equaling the requested number of Bytes' do
      r = get_random_number(32)
      r.class.must_equal(Bignum)
    end
  end

  describe 'get_random_number_with_bitlength' do
    it 'will return a Bignum' do
      bitlength = 256
      r = get_random_number_with_bitlength(bitlength)
      r.class.must_equal(Bignum)
    end

    it 'will return a random number of bitlength bits when bitlength is evenly divisible by 8' do
      bitlength = 256
      r = get_random_number_with_bitlength(bitlength)
      r.bit_length.must_equal(bitlength)
    end

    it 'will return a random number of bitlength bits when bitlength is not evenly divisible by 8' do
      bitlength = 257
      r = get_random_number_with_bitlength(bitlength)
      r.bit_length.must_equal(bitlength)
    end
  end

  describe 'miller_rabin_prime?' do
    it 'will return true for the known primes <= 100' do
      primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
      primes.each do |p|
        miller_rabin_prime?(p, 1000).must_equal(true)
      end
    end

    it 'will return true for 128 bit known primes' do
      # each generated with: get_prime_number(128)
      # each was also confirmed to be prime with Wolfram Alpha "Is N prime?"
      primes = [
        382767781724287998593870036291756450809,
        356939410756484930113231794428360705287,
        629759975992442345994901795062291065567,
        438321932766749553579901302755893165357,
        510959605072332037935633647489517878279
      ]

      primes.each do |p|
        miller_rabin_prime?(p, 1000).must_equal(true)
      end
    end

    it 'will return true for 512 bit known primes' do
      # each generated with: get_prime_number(512)
      # each was also confirmed to be prime with Wolfram Alpha "Is N prime?"
      primes = [
        23999707866903326489156183307465540658883197873852940711009335379108363305023805329984215621371398530337791438685939745980557830310369653441114726729488047,
        26264879364280914726387337523874770984938759192907578453587351353319032004165834289093747124468183487116687747810871530759960877154788799650863513281542449,
        21419943505124415306535132543073126636345087246929370277918349432585089088938166354019597382594479966007308711525355781449302321333323114286893173242617447,
        15374852860017642027686544538337536903565786542098241857812378775632595902540222017334241111772863426942525633588495075859043584856426724378984665496611453,
        20279656133141646288468910535277192664988817199276725796792464746874102110167503650047272184232978918686592075892731325814289300758175615144548978275489781
      ]

      primes.each do |p|
        miller_rabin_prime?(p, 1000).must_equal(true)
      end
    end

    it 'will return false for 128 bit known non-primes' do
      # each was also confirmed to NOT be prime with Wolfram Alpha "Is N prime?"
      # these are the same as the 128 bit primes + 2
      primes = [
        382767781724287998593870036291756450809 + 2,
        356939410756484930113231794428360705287 + 2,
        629759975992442345994901795062291065567 + 2,
        438321932766749553579901302755893165357 + 2,
        510959605072332037935633647489517878279 + 2
      ]

      primes.each do |p|
        miller_rabin_prime?(p, 1000).must_equal(false)
      end
    end
  end

  describe 'get_prime_number' do
    it 'will return a random prime odd number' do
      p = get_prime_number(128)
      p.odd?.must_equal(true)
    end

    it 'will return a random prime number of at least the specified bit length + 1' do
      bit_length = 128
      p = get_prime_number(bit_length)
      (p.bit_length >= bit_length + 1).must_equal(true)
    end

    it 'will return a random prime number that tests prime with the miller-rabin test' do
      p = get_prime_number(128)
      miller_rabin_prime?(p).must_equal(true)
    end
  end

  describe 'usafe_encode64 and usafe_decode64' do
    it 'will encode and decode back to the original String' do
      str = MultiJson.dump(:foo => 'bar', :bar => 12_345_678_748_390_743_789)
      enc = usafe_encode64(str)
      dec = usafe_decode64(enc)
      dec.must_equal(str)
    end
  end
end
