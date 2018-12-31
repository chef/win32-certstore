# coding: utf-8
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "win32/certstore/version"

Gem::Specification.new do |spec|
  spec.name          = "win32-certstore"
  spec.version       = Win32::Certstore::VERSION
  spec.authors       = ["nimisha"]
  spec.email         = ["nimisha.sharad@msystechnologies.com"]
  spec.license       = "Apache-2.0"
  spec.summary       = "Ruby library for accessing the certificate store on Windows."
  spec.homepage      = "https://github.com/chef/win32-certstore"

  spec.files         = Dir["LICENSE", "lib/**/*"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rspec", "~> 3.0"

  spec.add_dependency "mixlib-shellout"
  spec.add_dependency "ffi"
  spec.metadata["yard.run"] = "yri"
end
