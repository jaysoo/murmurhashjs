var binding = require("./build/default/murmurhash");

exports.MurmurHash = function(data, seed){
    seed = seed ? seed : 0;
    return binding.MurmurHash2A(data, seed);
}

exports.createMurmurHasher = function(seed){
    seed = seed ? seed : 0;
    return new binding.CMurmurHash2A(seed);
};
