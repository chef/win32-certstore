source "https://rubygems.org"

# Specify your gem's dependencies in win32-certstore.gemspec
gemspec

gem "rb-readline"

group(:development) do
  gem "pry"
end

group(:development, :test) do
  gem "rake"
  # for testing new chefstyle rules
  gem "chefstyle", git: "https://github.com/chef/chefstyle.git", branch: "master"
end
