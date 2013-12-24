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

include SecretSharing::Shamir

describe SecretSharing::Shamir do

  describe 'urlsafe_encode64 and urlsafe_decode64' do

    it 'will encode and decode back to the original String' do
      str = MultiJson.dump(:foo => 'bar', :bar => 12_345_678_748_390_743_789)
      enc = urlsafe_encode64(str)
      dec = urlsafe_decode64(enc)
      dec.must_equal(str)
    end

  end

end
