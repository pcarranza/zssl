require "optparse"

module Zoocial

  class OptionsParser

    attr_reader :mode, :source, :target, :key, :options

    def initialize
      @options =  { :key => File.expand_path('~/.ssh/id_rsa') }
      @parser = OptionParser.new do |opts|
        opts.banner = "usage: zssl [options] MODE [SOURCE] [TARGET]"
        opts.separator ""
        opts.separator "mode: e[ncrypt], using a public key or d[ecrypt] using a private key"
        opts.separator "source: the source file, stdin by default"
        opts.separator "target: the target file, stdout by default"
        opts.separator ""
        opts.on "-i", "--identity [FILE]", "Key identity file to encrypt or decrypt, DER or PEM encoded, by default it is your ssh key (~/.ssh/id_rsa)" do |id_rsa|
          @options[:key] = id_rsa
        end
        opts.separator ""
      end
    end

    def arguments
      ARGV
    end

    def parse
      @parser.parse!
    end

    def print_error e
      puts "#{$!}"
      puts ""
      puts @parser.help
      exit 1
    end

    def parse!
      begin
        parse
        mode, source, target = arguments
        @mode = parse_mode(mode)
        @source = source || $stdin
        @target = target || $stdout
        @key = @options.fetch(:key) { raise }
      rescue => e
        raise e unless print_error e
      end
    end

    private

    def parse_mode(mode)
      @mode = case mode
              when /^e(ncrypt)?$/i
                :encrypt
              when /^d(ecrypt)?$/i
                :decrypt
              else
                raise ArgumentError, "Mode is mandatory" if mode.nil? or mode.empty?
                raise ArgumentError, "Invalid mode '#{mode}'"
              end
    end
  end
end
