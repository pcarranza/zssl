require 'spec_helper'

executable = ["ruby", "-Ilib", "bin/zssl"]

describe "zssl" do
  it "Prints the help if no arguments are provided" do
    puts exec(*executable)
  end
end

BEGIN {
  testdir = File.dirname(File.expand_path(__FILE__))
  rootdir = File.dirname(testdir)
  Dir.chdir(rootdir)
}
