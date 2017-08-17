#
# Author:: Nimisha Sharad (<nimisha.sharad@msystechnologies.com>)
# Copyright:: Copyright (c) 2017 Chef Software, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'spec_helper'

describe Win32::Certstore do

  let (:certstore) { Win32::Certstore }

  describe "#open" do
    it "returns the certificate store handle if it exists" do
      allow(certstore).to receive(:CertOpenSystemStoreW).and_return("cert_handle")
      expect(certstore.open("My")).to eq("cert_handle")
    end

    it "raises error if CertOpenSystemStoreW method fails" do
      allow(certstore).to receive(:CertOpenSystemStoreW)
      allow(FFI::LastError).to receive(:error).and_return("err")
      expect{ certstore.open("My") }.to raise_error("Unable to open the Certificate Store `My` with error: err.")
    end
  end

  describe "#close" do
    it "returns true if the certificate is closed properly" do
      allow(certstore).to receive(:CertCloseStore).and_return(true)
      expect(certstore.close("My")).to be(true)
    end

    it "raises error if the certificate can't be closed" do
      allow(certstore).to receive(:CertCloseStore).and_return(false)
      allow(FFI::LastError).to receive(:error).and_return("err")
      expect{ certstore.close("My") }.to raise_error("Unable to close the Certificate Store with error: err.")
    end
  end
end
