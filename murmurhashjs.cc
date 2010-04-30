#include <v8.h>
#include "MurmurHash2A.h"

using namespace v8;

const char* ToCString(const v8::String::Utf8Value& value)
{
	  return *value ? *value : "<string conversion failed>";
}

Handle<Value> ComputeHash( const Arguments& args )
{
	if (args.Length() < 3)
	{
      return ThrowException( Exception::Error(String::New("MurmurHash2A requires three arguments")) );
    }

	if (!(args[0]->IsString() && args[1]->IsNumber() && args[2]->IsNumber()))
	{
      return ThrowException( Exception::Error(String::New("Invalid arguments to MurmurHash2A")) );
	}
	
	String::Utf8Value str( args[0] );
	const char* cstr = ToCString( str );
	int len = args[1]->Int32Value();
	unsigned int seed = args[2]->Uint32Value();

	return Integer::New( MurmurHash2A(cstr, len, seed) );
}

extern "C" void init ( Handle<Object> target )
{
	HandleScope scope;
	Local<FunctionTemplate> t = FunctionTemplate::New( ComputeHash );
	target->Set(
		String::New( "MurmurHash2A" ), 
		t->GetFunction()
	);
}
