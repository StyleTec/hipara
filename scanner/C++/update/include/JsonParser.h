/*****************************************************************
*
* Copyright (c) 2011 phorus, LLC.
* All rights reserved.
*
* ***************************************************************/
/**
*
* @file JsonParser.h
* @author Ping Gao
* @version 1.0
* @date 2013-07-09
*
* @description This class is responsible for parsing json response.
*
*/

#ifndef _JSON_H
#define _JSON_H

#ifndef json_char
   #define json_char char
#endif

#ifndef json_int_t
   #ifndef _MSC_VER
      #include <inttypes.h>
      #define json_int_t int64_t
   #else
      #define json_int_t __int64
   #endif
#endif



#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>





class JsonParser;
typedef struct
{
   unsigned long max_memory;
   int settings;
   /* Custom allocator support (leave null to use malloc/free)*/
   void* ( *mem_alloc ) (size_t, int zero, void * user_data);
   void ( *mem_free ) ( void*, void* user_data );
   void* user_data;  /* will be passed to mem_alloc and mem_free */

}json_settings;


typedef struct
{
   unsigned long used_memory;

   unsigned int uint_max;
   unsigned long ulong_max;

   json_settings settings;
   int first_pass;

}json_state;

#define json_relaxed_commas 1


#define e_off \
   ((int) (i - cur_line_begin))

#define whitespace \
   case '\n': ++ cur_line;  cur_line_begin = i; \
   case ' ': case '\t': case '\r'

#define string_add(b)  \
   do { if (!state.first_pass) string [string_length] = b;  ++ string_length; } while (0);

const static long
   flag_next             = 1 << 0,
   flag_reproc           = 1 << 1,
   flag_need_comma       = 1 << 2,
   flag_seek_value       = 1 << 3, 
   flag_escaped          = 1 << 4,
   flag_string           = 1 << 5,
   flag_need_colon       = 1 << 6,
   flag_done             = 1 << 7,
   flag_num_negative     = 1 << 8,
   flag_num_zero         = 1 << 9,
   flag_num_e            = 1 << 10,
   flag_num_e_got_sign   = 1 << 11,
   flag_num_e_negative   = 1 << 12;


typedef enum
{
   json_none,
   json_object,
   json_array,
   json_integer,
   json_double,
   json_string,
   json_boolean,
   json_null

} json_type;

extern const struct _json_value json_value_none;

typedef struct _json_value
{
   struct _json_value * parent;

   json_type type;

   union
   {
      int boolean;
      json_int_t integer;
      double dbl;

      struct
      {
         unsigned int length;
         json_char* ptr; /* null terminated */

      }string;

      struct
      {
         unsigned int length;

         struct
         {
            json_char * name;
            struct _json_value * value;

         } * values;

         #if defined(__cplusplus) && __cplusplus >= 201103L
         decltype(values) begin () const
         {  return values;
         }
         decltype(values) end () const
         {  return values + length;
         }
         #endif

      } object;

      struct
      {
         unsigned int length;
         struct _json_value ** values;

         #if defined(__cplusplus) && __cplusplus >= 201103L
         decltype(values) begin () const
         {  return values;
         }
         decltype(values) end () const
         {  return values + length;
         }
         #endif

      } array;

   } u;

   union
   {
      struct _json_value * next_alloc;
      void * object_mem;

   } _reserved;


   /* Some C++ operator sugar */

   #ifdef __cplusplus

      public:

         inline _json_value ()
         {  memset (this, 0, sizeof (_json_value));
         }

         inline const struct _json_value &operator [] (int index) const
         {
            if (type != json_array || index < 0
                     || ((unsigned int) index) >= u.array.length)
            {
               return json_value_none;
            }

            return *u.array.values [index];
         }

         inline const struct _json_value &operator [] (const char * index) const
         { 
            if (type != json_object)
               return json_value_none;

            for (unsigned int i = 0; i < u.object.length; ++ i)
               if (!strcmp (u.object.values [i].name, index))
                  return *u.object.values [i].value;

            return json_value_none;
         }

         inline operator const char * () const
         {  
            switch (type)
            {
               case json_string:
                  return u.string.ptr;

               default:
                  return "";
            };
         }

         inline operator json_int_t () const
         {  
            switch (type)
            {
               case json_integer:
                  return u.integer;

               case json_double:
                  return (json_int_t) u.dbl;

               default:
                  return 0;
            };
         }

         inline operator bool () const
         {  
            if (type != json_boolean)
               return false;

            return u.boolean != 0;
         }

         inline operator double () const
         {  
            switch (type)
            {
               case json_integer:
                  return (double) u.integer;

               case json_double:
                  return u.dbl;

               default:
                  return 0;
            };
         }

   #endif

}json_value;


using namespace std;

class JsonParser
{  
    private:
    json_value* json_parse( const json_char* json, size_t length );
    json_value* json_parse_ex( json_settings* settings, const json_char* json, size_t length, char * error );
 
    unsigned char hex_value( json_char c );
    void* json_alloc( json_state* state, unsigned long size, int zero );
    int new_value( json_state* state, json_value** top, json_value** root, json_value** alloc, json_type type );
    
    public:
    JsonParser();
    ~JsonParser();
    json_value* parseJson( const json_char* json, size_t length );
     
    void json_value_free( json_value* );
    /* Not usually necessary, unless you used a custom mem_alloc and now want to
     * use a custom mem_free.
     */
    void json_value_free_ex( json_settings* settings, json_value* );
}; 

#endif
