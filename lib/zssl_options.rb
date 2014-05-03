require "optparse"

module Zoocial

    class Options

        attr_reader :mode, :source, :target, :key

        def initialize
            @options = {}
            @parser = OptionParser.new do |opts|
                opts.banner = "usage: zssl [options] MODE [SOURCE] [TARGET]"
                opts.separator ""
                opts.separator "MODE: e[ncrypt], using a public key or d[ecrypt] using a private key"
                opts.separator "SOURCE: a file that exists, if it not declared stdin will be used"
                opts.separator "TARGET: a file that can exist or not, if it not declared stdout will be used"
                opts.separator ""
                opts.on "-i", "--identity [FILE]", "Key identity file to encrypt or decrypt, DER or PEM encoded, by default it is your ssh key (~/.ssh/id_rsa)" do |v|
                    @options[:key] = v
                end
                opts.separator ""
            end
        end

        def arguments
            return *ARGV
        end

        def options
            return @options
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
                @mode, @source, @target = arguments
                raise ArgumentError, "Mode is mandatory" if @mode.nil? or @mode.empty?
                if ['e', 'encrypt'].include? @mode.downcase
                    @mode = :encrypt
                elsif ['d', 'decrypt'].include? @mode.downcase
                    @mode = :decrypt
                else
                    raise ArgumentError, "Invalid mode '#{@mode}'"
                end

                open_file = Proc.new do |filename, mode, default|
                    if filename.nil?
                        default
                    else
                        raise ArgumentError, "File #{filename} could not be found" unless File.exists? filename or mode == 'w'
                        File.open filename, mode
                    end
                end

                options[:key] = local_ssh_pub_key unless options.has_key? :key and File.exists? local_ssh_pub_key
                raise ArgumentError, "No RSA key provided" unless options.has_key? :key

                @source = open_file.call @source, 'r', $stdin
                @target = open_file.call @target, 'w', $stdout
                @key = open_file.call options[:key], 'r'
                rescue => e
                    raise e unless print_error e
                end
            end

            private

            def local_ssh_pub_key
                File.expand_path('~/.ssh/id_rsa')
            end
        end
    end
