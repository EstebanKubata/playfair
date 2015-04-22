#define _GNU_SOURCE 1
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include "bplist.h"

uint64_t read_uint64(unsigned char* source)
{
   return ((uint64_t)source[0]) << 56 | ((uint64_t)source[1]) << 48 | ((uint64_t)source[2]) << 40 | ((uint64_t)source[3]) << 32 | ((uint64_t)source[4]) << 24 | ((uint64_t)source[5]) << 16 | ((uint64_t)source[6]) << 8 | ((uint64_t)source[7]);
      
}

uint32_t read_uint32(unsigned char* source)
{
   return source[0] << 24 | source[1] << 16 | source[2] << 8 | source[3];
}

uint16_t read_uint16(unsigned char* source)
{
   return (source[0] << 8) | source[1];
}

void read_trailer(unsigned char* data, int length, int* offsetSize, int* objectRefSize, uint64_t* numObjects, uint64_t* topObject, uint64_t* offsetTableOffset)
{
   unsigned char* trailer = &data[length-32];
   *offsetSize = trailer[6];
   *objectRefSize = trailer[7];
   *numObjects = read_uint64(&trailer[8]);
   *topObject = read_uint64(&trailer[16]);
   *offsetTableOffset = read_uint64(&trailer[24]);
}

uint64_t read_unknown_size(int size, unsigned char* source)
{
   uint64_t r = 0;
   for (int i = 0; i < size; i++)
      r = (r << 8) | source[i];
   return r;
}

void read_length_and_offset(char object_info, int offset, unsigned char* data, int* sub_length, int* sub_offset)
{
   *sub_length = object_info;
   *sub_offset = 1;
   if (object_info == 15)
   {
      char int_type = data[offset + 1] >> 4;
      char int_info = data[offset + 1] & 15;
      int int_length = 1 << int_info;
      *sub_offset = 2 + int_length;
      *sub_length = read_unknown_size(int_length, &data[offset+2]);
   }
}

void print_object(plist_node* n, int tab)
{
   int i, j;
   if (n == NULL)
   {
      printf("NULL");
   }
   else
   {
      switch(n->type)
      {
         case 0:
            printf("boolean: %d", n->value.boolean_value);
            break;
         case 1:
            printf("integer: %d", n->value.integer_value);
            break;
         case 2:
            printf("real: %f", n->value.double_value);
            break;
         case 4:
            printf("data: ");
            for (i = 0; i < n->value.data_value.length; i++)
               printf("%02X", n->value.data_value.data[i]);
            printf("");
            break;
         case 5:
            printf("string: %s", n->value.string_value);
            break;
         case 10:
            printf("array: [");
            tab+=8;
            for (i = 0; i < n->value.array_value.count; i++)
            {
               print_object(n->value.array_value.nodes[i], tab);
               if (i+1 < n->value.array_value.count)
                  printf(",\n ");
               else
                  printf("\n");
               for (j = 0; j < tab-1; j++) printf(" ");
            }
            printf("]");
            break;
         case 13:
            printf("dict: [");
            tab+=7;
            for (i = 0; i < n->value.dict_value.count; i++)
            {
               print_object(n->value.dict_value.nodes[i]->key, tab);
               printf(" = ");
               print_object(n->value.dict_value.nodes[i]->value, tab);
               if (i+1 < n->value.dict_value.count)
                  printf(",\n ");
               else
                  printf("\n");
               for (j = 0; j < tab-1; j++) printf(" ");
            }
            printf("]");
            break;
            
      }
   }   
}

plist_node* parse_object(uint64_t target, unsigned char* data, uint64_t* offset_table, int objectRefSize)
{
   uint64_t offset = offset_table[target];
   unsigned char key = data[offset];
   unsigned char object_type = key >> 4;
   unsigned char object_info = key & 15;
   plist_node* node = malloc(sizeof(plist_node));
   //printf("Reading object with id %d at %08x with key %02x\n", target, offset, key);
   node->type = object_type;
   switch(object_type)
   {
      case 0:  // primitive
      { 
         if (object_info == 8)
            node->value.boolean_value = 0;
         else if (object_info == 9)
            node->value.boolean_value = 1;
         else if (object_info == 0)
         {
            free(node);
            return NULL;
         }
         else
         {
            printf("Unhandled primitive: %d\n", object_info);
            assert(0);
         }
         return node;
      }
      case 1:  // integer
      {
         int length = 1 << object_info;
         char copy[length];
         memcpy(copy, &data[offset+1], length);
         node->value.integer_value = atoi(copy);
         return node;
      }
      case 2:  // real
      {
         int length = 1 << object_info;
         if (length == 4)
            node->value.double_value = ((float*)(&data[offset+1]))[0];
         else if (length == 8)
            node->value.double_value = ((double*)(&data[offset+1]))[0];
         else
         {
            printf("Bad real length: %d\n", length);
            assert(0);
         }
         return node;
      }
      case 4:  // data
      {
         int length;
         int sub_offset;
         read_length_and_offset(object_info, offset, data, &length, &sub_offset);         
         node->value.data_value.data = malloc(length);
         memcpy(node->value.data_value.data, &data[offset+sub_offset], length);
         node->value.data_value.length = length;
         return node;         
      }
      case 5:  // string
      {
         int length;
         int sub_offset;
         read_length_and_offset(object_info, offset, data, &length, &sub_offset);
         node->value.string_value = strndup((char*)&data[offset+sub_offset], length);
         return node;
      }
      case 10:  // array
      {
         int length;
         int sub_offset;
         read_length_and_offset(object_info, offset, data, &length, &sub_offset);
         node->value.array_value.nodes = malloc(sizeof(plist_node*) * length);
         node->value.array_value.count = length;
         for (int i = 0; i < length; i++)
         {
            uint64_t value_ref = read_unknown_size(objectRefSize, &data[offset + sub_offset + (i * objectRefSize)]);
            node->value.array_value.nodes[i] = parse_object(value_ref, data, offset_table, objectRefSize);
         }
         return node;
      }
      case 13:  // dict
      {
         int length;
         int sub_offset;
         read_length_and_offset(object_info, offset, data, &length, &sub_offset);
         node->value.dict_value.nodes = malloc(sizeof(plist_nvp*) * length);
         node->value.dict_value.count = length;
         //printf("Reading dict with %d items\n", length);
         for (int i = 0; i < length; i++)
         {
            node->value.dict_value.nodes[i] = malloc(sizeof(plist_nvp));
            uint64_t key_ref = read_unknown_size(objectRefSize, &data[offset + sub_offset + i * objectRefSize]);
            uint64_t value_ref = read_unknown_size(objectRefSize, &data[offset + sub_offset + (objectRefSize * length) + (i * objectRefSize)]);
            node->value.dict_value.nodes[i]->key = parse_object(key_ref, data, offset_table, objectRefSize);
            node->value.dict_value.nodes[i]->value = parse_object(value_ref, data, offset_table, objectRefSize);
         }
         return node;
      }
      default:
         printf("Not handled: %d\n", object_type);
         assert(0);
   }
}

void free_bplist(plist_node* node)
{
   int i;
   if (node == NULL)
      return;
   switch(node->type)
   {
      case 4:
         free(node->value.data_value.data);
         break;         
      case 5:
         free(node->value.string_value);
         break;         
      case 10:
         for (i = 0; i < node->value.array_value.count; i++)
            free_bplist(node->value.array_value.nodes[i]);
         free(node->value.array_value.nodes);
         break;         
      case 13:
         for (i = 0; i < node->value.dict_value.count; i++)
         {
            free_bplist(node->value.dict_value.nodes[i]->key);
            free_bplist(node->value.dict_value.nodes[i]->value);
            free_bplist(node->value.dict_value.nodes[i]);
         }
         free(node->value.dict_value.nodes);
         break;         
   }
   free(node);
}

plist_node* parse_bplist(unsigned char* data, int length)
{
   int minor, major, offsetSize, objectRefSize;
   uint64_t numObjects, topObject, offsetTableOffset;
   uint64_t* table;
   int i;
   assert((strncmp((char*)data, "bplist", 6) == 0));
   major = data[6] - '0';
   minor = data[6] - '0';
   read_trailer(data, length, &offsetSize, &objectRefSize, &numObjects, &topObject, &offsetTableOffset);
   table = malloc(sizeof(uint64_t) * numObjects);
   for (i = 0; i < numObjects; i++)
   {
      table[i] = read_unknown_size(offsetSize, &data[offsetTableOffset + i*offsetSize]);
   }
   plist_node* result = parse_object(topObject, data, table, objectRefSize);
   free(table);
   return result;
}


void retrieve_encrypted_keys(plist_node* root, unsigned char** param1, unsigned char** param2)
{
   int i;
   assert(root->type == 13);
   for (i = 0; i < root->value.dict_value.count; i++)
   {
      plist_node* key = root->value.dict_value.nodes[i]->key;
      plist_node* value = root->value.dict_value.nodes[i]->value;
      if (key->type == 5 && (strcmp(key->value.string_value, "param1") == 0) && value->type == 4)
      {
         *param1 = malloc(value->value.data_value.length);
         printf("param1 length: %d\n", value->value.data_value.length);
         memcpy(*param1, value->value.data_value.data, value->value.data_value.length);
      }
      else if (key->type == 5 && (strcmp(key->value.string_value, "param2") == 0) && value->type == 4)
      {
         *param2 = malloc(value->value.data_value.length);
         memcpy(*param2, value->value.data_value.data, value->value.data_value.length);
      }
   }
}
