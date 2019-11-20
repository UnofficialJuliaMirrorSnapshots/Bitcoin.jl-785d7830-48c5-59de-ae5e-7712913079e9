using Test, Bitcoin, BitcoinPrimitives, Sockets

# tests = ["rpc", "script", "tx", "CompactSizeUInt", "murmur3", "bloomfilter",  "address", "op", "helper", "network", "block"]
tests = ["tx", "rpc", "murmur3", "bloomfilter",  "address", "op", "helper", "network"]

for t ∈ tests
  include("$(t)test.jl")
end
