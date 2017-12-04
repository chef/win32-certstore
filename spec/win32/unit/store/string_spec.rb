require 'spec_helper'
require 'win32/certstore/mixin/string'

describe Win32::Certstore::Mixin::String do
  let(:string_class) { Class.new { include Win32::Certstore::Mixin::String } }
  subject(:string_obj) { string_class.new }

  context "when testing individual methods" do
    describe "#{}utf8_to_wide" do
      it  "converts utf8 to wide string" do
        wide_string = string_obj.utf8_to_wide("FOO")
        expect(wide_string.encoding).to eql(Encoding::UTF_16LE)
      end
    end

    describe "#{}wide_to_utf8" do
      it  "converts wide string to utf8 " do
        wide_string = string_obj.utf8_to_wide("FOO")
        utf8_string = string_obj.wide_to_utf8(wide_string)
        expect(utf8_string.encoding).to eql(Encoding::UTF_8)
      end
    end
  end
end
