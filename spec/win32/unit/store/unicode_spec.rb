require "spec_helper"
require "win32/certstore/mixin/unicode"

describe Win32::Certstore::Mixin::Unicode do
  context "when testing individual methods" do

    describe "#read_wstring", :windows_only do
      it "reads wide sring from Memory Pointer" do
        po = FFI::MemoryPointer.new(1, 120)
        po.write_string("()")
        expect(po.read_wstring).to eql("\u2928")
        po.clear
        expect(po.read_wstring).to eql("")
      end
    end
  end
end
