lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "win32/certstore/version"

Gem::Specification.new do |spec|
  spec.name          = "win32-certstore"
  spec.version       = Win32::Certstore::VERSION
  spec.authors       = ["Chef Software"]
  spec.email         = ["oss@chef.io"]
  spec.license       = "Apache-2.0"
  spec.summary       = "Ruby library for accessing the certificate stores on Windows."
  spec.homepage      = "https://github.com/chef/win32-certstore"

  spec.required_ruby_version = ">= 3.1"

  spec.files         = Dir["LICENSE", "lib/**/*"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rspec", "~> 3.13"

  spec.add_dependency "ffi", ">= 1.15.5", "< 1.17.0"
  spec.add_runtime_dependency "chef-powershell"
  spec.metadata["yard.run"] = "yri"
end
