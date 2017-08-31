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

require 'spec_helper'

describe Win32::Certstore do

  let (:certstore) { Win32::Certstore }
  
  describe "#list" do
    context "When passing empty certificate store name" do
      let (:store_name) { "" }
      it "Raise ArgumentError" do
        expect { certstore.open(store_name) }.to raise_error(ArgumentError)
      end
    end

    context "When passing invalid certificate store name" do
      let (:store_name) { "Chef" }
      it "Raise ArgumentError" do
        expect { certstore.open(store_name) }.to raise_error(ArgumentError)
      end
    end

    context "When passing empty certificate store name" do
      let (:store_name) { nil }
      it "Raise ArgumentError" do
        expect { certstore.open(store_name) }.to raise_error(ArgumentError)
      end
    end

    context "When passing valid certificate store name" do
      let (:store_name) { "root" }
      let (:root_certificate_name) { "Microsoft Root Certificate Authority"}
      before(:each) do
        allow_any_instance_of(Win32::Certstore::StoreBase).to receive(:cert_list).and_return([root_certificate_name])
      end
      it "return certificate list" do
        store = certstore.open(store_name)
        certificate_list = store.list
        expect(certificate_list.size).to eql(1)
        expect(certificate_list.first).to eql root_certificate_name
      end
    end

    context "When passing valid certificate store name" do
      let (:store_name) { "root" }
      before(:each) do
        allow_any_instance_of(Win32::Certstore::StoreBase).to receive(:cert_list).and_return([])
      end
      it "return no certificate list" do
        store = certstore.open(store_name)
        certificate_list = store.list
        expect(certificate_list.size).to eql(0)
      end
    end
  end
end
