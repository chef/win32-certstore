require 'spec_helper'
require 'win32/certstore/mixin/shell_out'

describe Win32::Certstore::Mixin::ShellOut do
  let(:string_class) { Class.new { include Win32::Certstore::Mixin::ShellOut } }
  subject(:string_obj) { string_class.new }

  context "when testing individual methods" do
    describe "#shell_out_Command" do
      it "executes shellout command" do
        cmd = "echo '#{rand(1000)}'"
        expect(string_obj).to receive(:shell_out_Command).with(cmd).and_return(true)
        string_obj.shell_out_Command(cmd)
      end

      it "raises Mixlib::ShellOut::ShellCommandFailed error if invalid command is passed" do
        cmd = "powershell.exe -Command -in 'abc'"
        expect{ string_obj.shell_out_command(cmd) }.to raise_error(Mixlib::ShellOut::ShellCommandFailed)
      end
    end
  end
end
