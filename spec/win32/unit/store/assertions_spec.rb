#
# Author:: Piyush Awasthi (<piyush.awasthi@msystechnologies.com>)
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
#

require "spec_helper"
require "win32/certstore/mixin/assertions"

describe Win32::Certstore::Mixin::Assertions do

  class Store
    include Win32::Certstore::Mixin::Assertions
  end

  let(:certstore) { Store.new }

  describe "#validate_store" do
    context "When passing empty certificate store name" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.validate_store(store_name) }.to raise_error("Empty Certificate Store.")
      end
    end

    context "When passing new certificate store name" do
      let(:store_name) { "Chef" }
      it "not raises ArgumentError" do
        expect { certstore.validate_store(store_name) }.not_to raise_error("Empty Certificate Store.")
      end
    end

    context "When passing empty certificate store name" do
      let(:store_name) { nil }
      it "raises ArgumentError" do
        expect { certstore.validate_store(store_name) }.to raise_error("Empty Certificate Store.")
      end
    end

    context "When passing valid certificate store name" do
      let(:store_name) { "root" }
      it "does not raise ArgumentError" do
        expect { certstore.validate_store(store_name) }.not_to raise_error(ArgumentError)
      end
    end
  end

  describe "#validate_certificate" do
    context "When not passing certificate file" do
      let(:cert_file_path) { "" }
      it "raises ArgumentError" do
        expect { certstore.validate_certificate(cert_file_path) }.to raise_error("Invalid Certificate format.")
      end
    end

    context "When passing invalid certificate" do
      let(:cert_file_path) { "Chef" }
      it "raises ArgumentError" do
        expect { certstore.validate_certificate(cert_file_path) }.to raise_error("Invalid Certificate format.")
      end
    end

    context "When passing nil" do
      let(:cert_file_path) { nil }
      it "raises ArgumentError" do
        expect { certstore.validate_certificate(cert_file_path) }.to raise_error("Invalid Certificate format.")
      end
    end

    context "When passing valid certificate file" do
      let(:cert_file_path) { '.\win32\assets\test.der' }
      it "does not raise ArgumentError" do
        expect { certstore.validate_certificate(cert_file_path) }.not_to raise_error(ArgumentError)
      end
    end
  end
end
