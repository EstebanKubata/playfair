struct plist_node
{
   int type;
   union
   {
      struct
      {
         struct plist_nvp** nodes;
         int count;
      } dict_value;
      struct
      {
         struct plist_node** nodes;
         int count;
      } array_value;
      int boolean_value;
      double double_value;
      int integer_value;
      char* string_value;
      struct
      {
         unsigned char* data;
         int length;
      } data_value;
   } value;
};

typedef struct plist_node plist_node;


struct plist_nvp
{
   struct plist_node* key;
   struct plist_node* value;
};

typedef struct plist_nvp plist_nvp;

plist_node* parse_bplist(unsigned char* data, int length);
void free_bplist(plist_node* bplist);
void retrieve_encrypted_keys(plist_node* root, unsigned char** param1, unsigned char** param2);
