#include <v8.h>

#include <node.h>
#include <node_buffer.h>
#include <string>
#include <stdlib.h>

#include <errno.h>

//-----------------------------------------------------------------------------
// MurmurHash2A, by Austin Appleby

// This is a variant of MurmurHash2 modified to use the Merkle-Damgard
// construction. Bulk speed should be identical to Murmur2, small-key speed
// will be 10%-20% slower due to the added overhead at the end of the hash.

// This variant fixes a minor issue where null keys were more likely to
// collide with each other than expected, and also makes the algorithm
// more amenable to incremental implementations. All other caveats from
// MurmurHash2 still apply.

using namespace v8;
using namespace node;


#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }


unsigned int MurmurHash2A ( const void * key, int len, unsigned int seed )
{
    const unsigned int m = 0x5bd1e995;
    const int r = 24;
    unsigned int l = len;

    const unsigned char * data = (const unsigned char *)key;

    unsigned int h = seed;

    while(len >= 4)
    {
        unsigned int k = *(unsigned int*)data;

        mmix(h,k);

        data += 4;
        len -= 4;
    }

    unsigned int t = 0;

    switch(len)
    {
        case 3: t ^= data[2] << 16;
        case 2: t ^= data[1] << 8;
        case 1: t ^= data[0];
    };

    mmix(h,t);
    mmix(h,l);


    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return h;
}


Handle<Value> ComputeHash( const Arguments& args )
{
  HandleScope scope;

  if (args.Length() < 2)
	{
      return ThrowException( Exception::Error(String::New("MurmurHash2A requires two arguments (data, seed)")) );
    }
  
  if (!args[1]->IsNumber())
	{
      return ThrowException( Exception::Error(String::New("Invalid arguments to MurmurHash2A")) );
	}

  // taken from node_crypto.cc Hash implementation
  enum encoding enc = BINARY;
  ssize_t len = DecodeBytes(args[0], enc);

  if (len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }
    
  char* buf = new char[len];
  ssize_t written = DecodeWrite(buf, len, args[0], enc);
  assert(written == len);

  unsigned int seed = args[1]->Uint32Value();
  
  return scope.Close(Number::New(MurmurHash2A(buf, len, seed)));
}


class CMurmurHash2A : public ObjectWrap {
public:
  static void Initialize (v8::Handle<v8::Object> target) {
    HandleScope scope;
    
    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "add", Add);
    NODE_SET_PROTOTYPE_METHOD(t, "end", End);

    target->Set(String::NewSymbol("CMurmurHash2A"), t->GetFunction());
  }

  bool Begin (unsigned int seed = 0) {
    m_hash  = seed;
    m_tail  = 0;
    m_count = 0;
    m_size  = 0;
    hasended_ = false;
    return true;
  }

  //void Add(const unsigned char* data, int len) {
  void Add(const void * key, int len) {

    if ( hasended_ ) { return; };

    const unsigned char * data = (const unsigned char *)key;

    m_size += len;
    
    MixTail(data, len);
    
    while(len >= 4)
      {
        unsigned int k = *(unsigned int*)data;
        
        mmix(m_hash,k);
        
        data += 4;
        len -= 4;
      }
    
    MixTail(data, len);

  }
  
  unsigned int End( void ) {
    mmix(m_hash,m_tail);
    mmix(m_hash,m_size);
    
    m_hash ^= m_hash >> 13;
    m_hash *= m;
    m_hash ^= m_hash >> 15;

    // hash no more
    hasended_ = true;

    return m_hash;
  }

protected:
  
  static Handle<Value> New (const Arguments& args) {
    HandleScope scope;

    CMurmurHash2A *mmhash = new CMurmurHash2A();

    if (args.Length() == 1){
      if(!args[0]->IsUint32()) { 
        return ThrowException(Exception::Error(String::New(
        "Seed argument should be an integer")));
      }
      mmhash->Wrap(args.This());
      unsigned int seed = args[0]->Uint32Value();
    
      mmhash->Begin(seed);
    } else {
      mmhash->Begin();
    }

    return args.This();
  }

  static Handle<Value> Add(const Arguments& args) {
    HandleScope scope;

    CMurmurHash2A *mmhash = ObjectWrap::Unwrap<CMurmurHash2A>(args.This());
    if (mmhash->hasended_){
      Local<Value> exception = Exception::Error(String::New("Hasher has already ended."));
      return ThrowException(exception);
    }
    
    // taken from node_crypto.cc Hash implementation
    enum encoding enc = BINARY;
    ssize_t len = DecodeBytes(args[0], enc);
    
    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }
    
    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], enc);
    assert(written == len);

    mmhash->Add(buf, len);

    delete[] buf;

    return args.This();
  }


  static Handle<Value> End(const Arguments& args) {
    CMurmurHash2A *mmhash = ObjectWrap::Unwrap<CMurmurHash2A>(args.This());
    
    HandleScope scope;
    unsigned int retval = mmhash->End();

    // returning a Number since Integer or Uint32 are signed ints in js
    return scope.Close(Number::New(retval));
  }
  
private:

  static const unsigned int m = 0x5bd1e995;
  static const int r = 24;

  void MixTail (const unsigned char * & data, int & len )
  {
    while( len && ((len<4) || m_count) )
      {
        m_tail |= (*data++) << (m_count * 8);
        
        m_count++;
        len--;
        
        if(m_count == 4)
          {
            mmix(m_hash,m_tail);
            m_tail = 0;
            m_count = 0;
          }
      }
  }

  unsigned int m_hash;
  unsigned int m_tail;
  unsigned int m_count;
  unsigned int m_size;
  bool hasended_;
};

extern "C" void 
init (v8::Handle<Object> target)
{
  HandleScope scope;
  // One-shot hash
  Local<FunctionTemplate> t = FunctionTemplate::New( ComputeHash );
  target->Set( String::New( "MurmurHash2A" ), t->GetFunction() );
  // Incremental hash
  CMurmurHash2A::Initialize( target );
}
