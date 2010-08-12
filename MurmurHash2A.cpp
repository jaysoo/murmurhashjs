//-----------------------------------------------------------------------------
// MurmurHash2A, by Austin Appleby

// This is a variant of MurmurHash2 modified to use the Merkle-Damgard
// construction. Bulk speed should be identical to Murmur2, small-key speed
// will be 10%-20% slower due to the added overhead at the end of the hash.

// This variant fixes a minor issue where null keys were more likely to
// collide with each other than expected, and also makes the algorithm
// more amenable to incremental implementations. All other caveats from
// MurmurHash2 still apply.

#include <stdio.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <fstream>


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

//-----------------------------------------------------------------------------
// CMurmurHash2A, by Austin Appleby

// This is a sample implementation of MurmurHash2A designed to work
// incrementally.

// Usage -

// CMurmurHash2A hasher
// hasher.Begin(seed);
// hasher.Add(data1,size1);
// hasher.Add(data2,size2);
// ...
// hasher.Add(dataN,sizeN);
// unsigned int hash = hasher.End()

class CMurmurHash2A
{
public:

	void Begin ( unsigned int seed = 0 )
	{
		m_hash  = seed;
		m_tail  = 0;
		m_count = 0;
		m_size  = 0;
	}

	void Add ( const unsigned char * data, int len )
	{
		m_size += len;

		MixTail(data,len);

		while(len >= 4)
		{
			unsigned int k = *(unsigned int*)data;

			mmix(m_hash,k);

			data += 4;
			len -= 4;
		}

		MixTail(data,len);
	}

	unsigned int End ( void )
	{
		mmix(m_hash,m_tail);
		mmix(m_hash,m_size);

		m_hash ^= m_hash >> 13;
		m_hash *= m;
		m_hash ^= m_hash >> 15;

		return m_hash;
	}

private:

	static const unsigned int m = 0x5bd1e995;
	static const int r = 24;

	void MixTail ( const unsigned char * & data, int & len )
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
};

// compile with `g++ -o generate_hash_values MurmurHash2A.cpp` to get
// a few (silly) sample hashes
int main(int argc,
     char* argv[])
{
  // a list of hashes for ever longer strings of zeroes ("0", "00",
  // "000" and so on)
  int res;
  for(int i=1;i<33;i++){
    char*s = (char*)std::string(i, '0').c_str();
    res = MurmurHash2A(s, i, 0);
    printf("%d: %u\n", i, res);
  }
  // test
  char s[5] = "test";
  res = MurmurHash2A(s, 4, 0);
  printf("test: %u\n", res);

  // 123 
  char s2[4] = "123";
  res = MurmurHash2A(s2, 3, 0);
  printf(" 123: %u\n", res);

  // reading a file in binary mode
  std::ifstream image;
  image.open("./wscript", std::ios::in | std::ios::binary);

  image.seekg (0, std::ios::end);
  int n = image.tellg();
  image.seekg (0, std::ios::beg);

  char* data = new char[n];

  image.read(data, n);
  image.close();
  res = MurmurHash2A(data, n, 0);
  printf("file: %u\n", res);

  delete [] data;

  return 0;
}
