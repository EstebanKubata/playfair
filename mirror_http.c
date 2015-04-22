#define _XOPEN_SOURCE 600
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

#ifdef HAVE_OPENMAX
#include "bcm_host.h"
#include "ilclient.h"
#endif

#define ANNEX_B 1

// This requires libavahi-compat-libdnssd-dev if you want to build on Linux 

void generate_key_schedule(unsigned char* key_material, uint32_t key_schedule[11][4]);
void generate_session_key(unsigned char* oldSap, unsigned char* messageIn, unsigned char* sessionKey);
void cycle(unsigned char* block, uint32_t key_schedule[11][4]);
void z_xor(unsigned char* in, unsigned char* out, int blocks);
void x_xor(unsigned char* in, unsigned char* out, int blocks);

extern unsigned char default_sap[];

unsigned char* fairplay_decrypt(char* message3, unsigned char* cipherText)
{
   unsigned char* chunk1 = &cipherText[16];
   unsigned char* chunk2 = &cipherText[56];
   int i;
   unsigned char blockIn[16];
   unsigned char* keyOut = malloc(16);
   unsigned char sapKey[16];
   uint32_t key_schedule[11][4];
   generate_session_key(default_sap, (unsigned char*)message3, sapKey);   
   generate_key_schedule(sapKey, key_schedule);
   z_xor(chunk2, blockIn, 1);
   cycle(blockIn, key_schedule);
   for (i = 0; i < 16; i++)
      keyOut[i] = blockIn[i] ^ chunk1[i];
   x_xor(keyOut, keyOut, 1);
   z_xor(keyOut, keyOut, 1);
   return keyOut;
}


typedef struct
{
   uint32_t length;
   uint16_t type;
   uint16_t signature;
   uint64_t timestamp;
   char     padding[112];
} video_header;


/* A tiny kinda-HTTP server. This is hopelessly inefficient (reads the headers one byte at a time!) but very short and simple */

void exit_thread(int fd, char* reason)
{
   close(fd);
   printf("Exiting thread: %s\n", reason);
   pthread_exit(0);
}


int read_line_to_codes(int fd, char* buffer, int max)
{
   *buffer = 0;
   while(max > 0)
   {
      int r = recv(fd, buffer, 1, 0);
      if (r < 0)
         exit_thread(fd, "IO error: Read");
      if (*buffer == 10)
      {
         *(buffer-1) = 0;
         return 1;
      }
      buffer++;
      max--;
   }
   return 0;  // not enough space
}

void send_buffer(int fd, char* buffer, int len)
{
   if (len == -1)
      len = strlen(buffer);
   int ptr = 0;
   int r = 0;
   while(ptr < len)
   {
      r = send(fd, &buffer[ptr], len-ptr, 0);
      if (r < 0)
         exit_thread(fd, "IO error: Write");
      ptr += r;
   }
}

void read_body(int fd, char* buffer, int len)
{
   int ptr = 0;
   int r = 0;
   while(ptr < len)
   {
      r = recv(fd, &buffer[ptr], len-ptr, 0);
      if (r < 0)
         exit_thread(fd, "IO error: Read");
      ptr += r;
   }
}

int buffer_prefix(char* s, char* prefix)
{
   while(1)
   {
      if (*s != *prefix)
         return 0;
      prefix++;
      s++;
      if (*prefix == 0)
         return 1;
   }
}

void parse_headers(int fd, int* content_length, char* seq)
{
   char buffer[1024];
   *content_length = 0;
   while(1)
   {
      assert(read_line_to_codes(fd, buffer, 1024));
      if (buffer_prefix(buffer, "Content-Length:"))
         *content_length = atoi(&buffer[15]);
      if (buffer_prefix(buffer, "CSeq:"))
         strcpy(seq, &buffer[5]);
      else if (buffer[0] == 0)
         break;
   }
}

// These are pre-computed. We use the same key material each time, so the first message we send depends only on the mode-byte in the initial message
char reply_message[4][142] = {{0x46,0x50,0x4c,0x59,0x03,0x01,0x02,0x00,0x00,0x00,0x00,0x82,0x02,0x00,0x0f,0x9f,0x3f,0x9e,0x0a,0x25,0x21,0xdb,0xdf,0x31,0x2a,0xb2,0xbf,0xb2,0x9e,0x8d,0x23,0x2b,0x63,0x76,0xa8,0xc8,0x18,0x70,0x1d,0x22,0xae,0x93,0xd8,0x27,0x37,0xfe,0xaf,0x9d,0xb4,0xfd,0xf4,0x1c,0x2d,0xba,0x9d,0x1f,0x49,0xca,0xaa,0xbf,0x65,0x91,0xac,0x1f,0x7b,0xc6,0xf7,0xe0,0x66,0x3d,0x21,0xaf,0xe0,0x15,0x65,0x95,0x3e,0xab,0x81,0xf4,0x18,0xce,0xed,0x09,0x5a,0xdb,0x7c,0x3d,0x0e,0x25,0x49,0x09,0xa7,0x98,0x31,0xd4,0x9c,0x39,0x82,0x97,0x34,0x34,0xfa,0xcb,0x42,0xc6,0x3a,0x1c,0xd9,0x11,0xa6,0xfe,0x94,0x1a,0x8a,0x6d,0x4a,0x74,0x3b,0x46,0xc3,0xa7,0x64,0x9e,0x44,0xc7,0x89,0x55,0xe4,0x9d,0x81,0x55,0x00,0x95,0x49,0xc4,0xe2,0xf7,0xa3,0xf6,0xd5,0xba},
                              {0x46,0x50,0x4c,0x59,0x03,0x01,0x02,0x00,0x00,0x00,0x00,0x82,0x02,0x01,0xcf,0x32,0xa2,0x57,0x14,0xb2,0x52,0x4f,0x8a,0xa0,0xad,0x7a,0xf1,0x64,0xe3,0x7b,0xcf,0x44,0x24,0xe2,0x00,0x04,0x7e,0xfc,0x0a,0xd6,0x7a,0xfc,0xd9,0x5d,0xed,0x1c,0x27,0x30,0xbb,0x59,0x1b,0x96,0x2e,0xd6,0x3a,0x9c,0x4d,0xed,0x88,0xba,0x8f,0xc7,0x8d,0xe6,0x4d,0x91,0xcc,0xfd,0x5c,0x7b,0x56,0xda,0x88,0xe3,0x1f,0x5c,0xce,0xaf,0xc7,0x43,0x19,0x95,0xa0,0x16,0x65,0xa5,0x4e,0x19,0x39,0xd2,0x5b,0x94,0xdb,0x64,0xb9,0xe4,0x5d,0x8d,0x06,0x3e,0x1e,0x6a,0xf0,0x7e,0x96,0x56,0x16,0x2b,0x0e,0xfa,0x40,0x42,0x75,0xea,0x5a,0x44,0xd9,0x59,0x1c,0x72,0x56,0xb9,0xfb,0xe6,0x51,0x38,0x98,0xb8,0x02,0x27,0x72,0x19,0x88,0x57,0x16,0x50,0x94,0x2a,0xd9,0x46,0x68,0x8a},
                              {0x46,0x50,0x4c,0x59,0x03,0x01,0x02,0x00,0x00,0x00,0x00,0x82,0x02,0x02,0xc1,0x69,0xa3,0x52,0xee,0xed,0x35,0xb1,0x8c,0xdd,0x9c,0x58,0xd6,0x4f,0x16,0xc1,0x51,0x9a,0x89,0xeb,0x53,0x17,0xbd,0x0d,0x43,0x36,0xcd,0x68,0xf6,0x38,0xff,0x9d,0x01,0x6a,0x5b,0x52,0xb7,0xfa,0x92,0x16,0xb2,0xb6,0x54,0x82,0xc7,0x84,0x44,0x11,0x81,0x21,0xa2,0xc7,0xfe,0xd8,0x3d,0xb7,0x11,0x9e,0x91,0x82,0xaa,0xd7,0xd1,0x8c,0x70,0x63,0xe2,0xa4,0x57,0x55,0x59,0x10,0xaf,0x9e,0x0e,0xfc,0x76,0x34,0x7d,0x16,0x40,0x43,0x80,0x7f,0x58,0x1e,0xe4,0xfb,0xe4,0x2c,0xa9,0xde,0xdc,0x1b,0x5e,0xb2,0xa3,0xaa,0x3d,0x2e,0xcd,0x59,0xe7,0xee,0xe7,0x0b,0x36,0x29,0xf2,0x2a,0xfd,0x16,0x1d,0x87,0x73,0x53,0xdd,0xb9,0x9a,0xdc,0x8e,0x07,0x00,0x6e,0x56,0xf8,0x50,0xce},
                              {0x46,0x50,0x4c,0x59,0x03,0x01,0x02,0x00,0x00,0x00,0x00,0x82,0x02,0x03,0x90,0x01,0xe1,0x72,0x7e,0x0f,0x57,0xf9,0xf5,0x88,0x0d,0xb1,0x04,0xa6,0x25,0x7a,0x23,0xf5,0xcf,0xff,0x1a,0xbb,0xe1,0xe9,0x30,0x45,0x25,0x1a,0xfb,0x97,0xeb,0x9f,0xc0,0x01,0x1e,0xbe,0x0f,0x3a,0x81,0xdf,0x5b,0x69,0x1d,0x76,0xac,0xb2,0xf7,0xa5,0xc7,0x08,0xe3,0xd3,0x28,0xf5,0x6b,0xb3,0x9d,0xbd,0xe5,0xf2,0x9c,0x8a,0x17,0xf4,0x81,0x48,0x7e,0x3a,0xe8,0x63,0xc6,0x78,0x32,0x54,0x22,0xe6,0xf7,0x8e,0x16,0x6d,0x18,0xaa,0x7f,0xd6,0x36,0x25,0x8b,0xce,0x28,0x72,0x6f,0x66,0x1f,0x73,0x88,0x93,0xce,0x44,0x31,0x1e,0x4b,0xe6,0xc0,0x53,0x51,0x93,0xe5,0xef,0x72,0xe8,0x68,0x62,0x33,0x72,0x9c,0x22,0x7d,0x82,0x0c,0x99,0x94,0x45,0xd8,0x92,0x46,0xc8,0xc3,0x59}};

char fp_header[] = {0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x14};

#ifdef HAVE_OPENMAX
typedef struct
{
   TUNNEL_T tunnel[4];
   int port_settings_changed;
   COMPONENT_T *video_decode, *video_scheduler, *video_render, *clock;
   OMX_BUFFERHEADERTYPE *buffer;
   int first_packet;
} decoder_state_t;
#endif

void* configure_display_device()
{
#ifdef HAVE_OPENMAX
   OMX_VIDEO_PARAM_PORTFORMATTYPE format;
   OMX_TIME_CONFIG_CLOCKSTATETYPE cstate;
   ILCLIENT_T *client;   
   decoder_state_t* ctx = malloc(sizeof(decoder_state_t));
   memset(ctx, 0, sizeof(decoder_state_t));
   ctx->first_packet = 1;

   assert(client = ilclient_init());
   assert(OMX_Init() == OMX_ErrorNone);

   assert(ilclient_create_component(client, &ctx->video_decode, "video_decode", ILCLIENT_DISABLE_ALL_PORTS | ILCLIENT_ENABLE_INPUT_BUFFERS) == 0);
   assert(ilclient_create_component(client, &ctx->video_render, "video_render", ILCLIENT_DISABLE_ALL_PORTS) == 0);
   assert(ilclient_create_component(client, &ctx->clock, "clock", ILCLIENT_DISABLE_ALL_PORTS) == 0);
   memset(&cstate, 0, sizeof(cstate));
   cstate.nSize = sizeof(cstate);
   cstate.nVersion.nVersion = OMX_VERSION;
   cstate.eState = OMX_TIME_ClockStateWaitingForStartTime;
   cstate.nWaitMask = 1;
   assert(OMX_SetParameter(ILC_GET_HANDLE(ctx->clock), OMX_IndexConfigTimeClockState, &cstate) == OMX_ErrorNone);
   assert(ilclient_create_component(client, &ctx->video_scheduler, "video_scheduler", ILCLIENT_DISABLE_ALL_PORTS) == 0);
   set_tunnel(ctx->tunnel, ctx->video_decode, 131, ctx->video_scheduler, 10);
   set_tunnel(ctx->tunnel+1, ctx->video_scheduler, 11, ctx->video_render, 90);
   set_tunnel(ctx->tunnel+2, ctx->clock, 80, ctx->video_scheduler, 12);
   assert(ilclient_setup_tunnel(ctx->tunnel+2, 0, 0) == 0);
   ilclient_change_component_state(ctx->clock, OMX_StateExecuting);
   ilclient_change_component_state(ctx->video_decode, OMX_StateIdle);
   memset(&format, 0, sizeof(OMX_VIDEO_PARAM_PORTFORMATTYPE));
   format.nSize = sizeof(OMX_VIDEO_PARAM_PORTFORMATTYPE);
   format.nVersion.nVersion = OMX_VERSION;
   format.nPortIndex = 130;
   format.eCompressionFormat = OMX_VIDEO_CodingAVC;
   assert(OMX_SetParameter(ILC_GET_HANDLE(ctx->video_decode), OMX_IndexParamVideoPortFormat, &format) == OMX_ErrorNone);
   assert(ilclient_enable_port_buffers(ctx->video_decode, 130, NULL, NULL, NULL) == 0);
   ilclient_change_component_state(ctx->video_decode, OMX_StateExecuting);
   printf("Created a video decoder\n");
   return ctx;
#else
   printf("Will dump to file\n");
   return fopen("/tmp/video.264", "wb");
#endif
}

void data_ready(void* render_ctx, unsigned char* buffer, int length)
{
#ifdef HAVE_OPENMAX
   int ptr = 0;
   decoder_state_t* ctx = (decoder_state_t*)render_ctx;
   OMX_BUFFERHEADERTYPE* video_buffer = ilclient_get_input_buffer(ctx->video_decode, 130, 1);      
   if (ctx->port_settings_changed == 0 && ilclient_remove_event(ctx->video_decode, OMX_EventPortSettingsChanged, 131, 0, 0, 1) == 0)
   {
      printf("Port settings changed\n");
      ctx->port_settings_changed = 1;
      assert(ilclient_setup_tunnel(ctx->tunnel, 0, 0) == 0);
      ilclient_change_component_state(ctx->video_scheduler, OMX_StateExecuting);
      assert(ilclient_setup_tunnel(ctx->tunnel+1, 0, 1000) == 0);
      ilclient_change_component_state(ctx->video_render, OMX_StateExecuting);
   }
   // Do not overflow the video buffer!
   while (ptr < length)
   {
      int this_chunk = length - ptr;
      if (this_chunk > video_buffer->nAllocLen)
         this_chunk = video_buffer->nAllocLen;
      memcpy(video_buffer->pBuffer, &buffer[ptr], this_chunk);
      video_buffer->nFilledLen = this_chunk;
      video_buffer->nOffset = 0;
      if (ctx->first_packet)
      {
         video_buffer->nFlags = OMX_BUFFERFLAG_STARTTIME;
         ctx->first_packet = 0;
      }
      else
         video_buffer->nFlags = OMX_BUFFERFLAG_TIME_UNKNOWN;
      assert(OMX_EmptyThisBuffer(ILC_GET_HANDLE(ctx->video_decode), video_buffer) == OMX_ErrorNone);
      ptr += this_chunk;
   }
#else
   assert(fwrite(buffer, 1, length, (FILE*)render_ctx) == length);
   fflush((FILE*)render_ctx);         
#endif
}

void codec_data_ready(void* render_ctx, unsigned char* buffer, int length)
{
#ifdef HAVE_OPENMAX
   // This will muck up the video pipeline. We have to get the port settings changed event, then recreate the tunnels
   decoder_state_t* ctx = (decoder_state_t*)render_ctx;
   ctx->port_settings_changed = 0;
   
#endif
   data_ready(render_ctx, buffer, length);
}


void process_stream(int fd, unsigned char* keybytes, unsigned char* ivbytes)
{
   AES_KEY key;
   AES_set_encrypt_key(keybytes, 128, &key);

   int naluSize = 0;
   unsigned char nal[] = {0, 0, 0, 1};      
   unsigned char slice_header[] = {0, 0, 0, 1, 5, 0x88, 0x84, 0x21, 0xa0};
   unsigned int num = 0;
   unsigned char ecount[16];
   void* ctx = configure_display_device();
   
   while(1)
   {
      video_header header;         
      read_body(fd, (char*)&header, 128);
      switch(header.type)
      {
         case 0: // video data
         {
            int i;
            unsigned char input[header.length]; 
            unsigned char output[header.length]; 
            // Read in a block and decrypt using CTR mode
            read_body(fd, (char*)input, header.length);
            AES_ctr128_encrypt(input, output, header.length, &key, ivbytes, ecount, &num);
#ifdef ANNEX_B
            int ptr2, ptr = 0;
            unsigned char emulation = 0x03;
            while(ptr < header.length)
            {
               uint32_t length = ntohl(((uint32_t*)(&output[ptr]))[0]);
               ptr += 4;
               int nal_end = ptr+length;
               data_ready(ctx, slice_header, 4);
               // Need to check for 0x00000000, 0x00000001 and 0x00000002 and insert a 0x03 'emulation prevention' byte
               while(ptr < nal_end)
               {
                  ptr2 = ptr+3;
                  while(ptr2 < nal_end)
                  {
                     if (output[ptr2-3] == 00 && output[ptr2-2] == 00 && output[ptr2-1] == 00 && output[ptr2] < 3)
                        break;
                     ptr2++;
                  }
                  if (ptr2 > nal_end)
                     ptr2 = nal_end;
                  data_ready(ctx, &output[ptr], ptr2-ptr);
                  if (ptr2 < nal_end)
                     data_ready(ctx, &emulation, 1);
                  ptr = ptr2;
               }
            }
#else
            data_ready(ctx, output, header.length);
#endif
            break;            
         }
         case 1:   // codec info
         {
            unsigned char data[header.length];
            unsigned char nal_data[256];
            int sps_size = 0;
            int pps_size = 0;
            read_body(fd, (char*)data, header.length);
            printf("Codec info has been supplied...\n");
#ifdef ANNEX_B            
            sps_size = data[6] << 8| data[7];
            memcpy(nal_data, nal, 4);
            //data_ready(ctx, nal, 4);
            //data_ready(ctx, &data[8], sps_size);
            memcpy(&nal_data[4], &data[8], sps_size);
            pps_size = data[9+sps_size] << 8 | data[10+sps_size];
            //data_ready(ctx, nal, 4);
            memcpy(&nal_data[4+sps_size], nal, 4);            
            //data_ready(ctx, &data[11+sps_size], pps_size);
            memcpy(&nal_data[8+sps_size], &data[11+sps_size], pps_size);
            codec_data_ready(ctx, nal_data, 8+sps_size+pps_size);
#else
            data_ready(ctx, data, header.length);
#endif
            naluSize = (data[4] & 3) + 1;
            assert(naluSize == 4);
            break;
         }
         case 2:   // heartbeat
         {
            // heartbeat is not meant to have a payload, but sometimes it does?
            unsigned char data[header.length];
            read_body(fd, (char*)data, header.length);
            break;
         }
      }
   }
}

float rate = 0;
float position = 0;
float duration = 1200;

void* http_worker(void* pfd)
{
   char* aesKey;
   int fd = *((int*)pfd);
   free(pfd);
   char buffer[1024];
   char* message3;
   while(1)
   {
      if (!read_line_to_codes(fd, buffer, 1024))
         exit_thread(fd, "Could not read command");
      printf("Command: %s\n", buffer);
      if (buffer_prefix(buffer, "POST /fp-"))
      {
         char cseq[8];
         int content_length;
         parse_headers(fd, &content_length, cseq);
         char* fp_message = malloc(content_length);
         int seq = 0;
         read_body(fd, fp_message, content_length);
         seq = fp_message[6];
         if (seq == 1)
         {
            int mode = fp_message[14];
            send_buffer(fd, "RTSP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nX-Apple-ET: 32\r\nContent-Length: 142\r\nServer: AirTunes/150.33\r\nCSeq:", -1);
            send_buffer(fd, cseq, -1);
            send_buffer(fd, "\r\n\r\n", -1);
            send_buffer(fd, reply_message[mode], 142);
            free(fp_message);
         }
         else if (seq == 3)
         {
            send_buffer(fd, "RTSP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nX-Apple-ET: 32\r\nContent-Length: 32\r\nServer: AirTunes/150.33\r\nCSeq:", -1);
            send_buffer(fd, cseq, -1);
            send_buffer(fd, "\r\n\r\n", -1);            
            send_buffer(fd, fp_header, 12);
            send_buffer(fd, &fp_message[content_length - 20], 20);
            message3 = fp_message;
         }
      }
      else if (buffer_prefix(buffer, "POST /stream"))
      {
         // Note that the stream might NOT be encrypted!
         printf("Incoming stream...\n");
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         unsigned char* bplist = malloc(content_length);
         unsigned char* fpAesKey = NULL;
         unsigned char* aesKey = NULL;
         unsigned char* aesIv = NULL;
         read_body(fd, (char*)bplist, content_length);
         plist_node* root = parse_bplist(bplist, content_length);
         retrieve_encrypted_keys(root, &fpAesKey, &aesIv);
         aesKey = fairplay_decrypt(message3, fpAesKey);
         free(message3);
         process_stream(fd, aesKey, aesIv);
      }
      else if (buffer_prefix(buffer, "OPTIONS *"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         send_buffer(fd, "RTSP/1.0 200 OK\r\nPublic: ANNOUNCE, SETUP, PLAY, DESCRIBE, REDIRECT, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET\r\nServer: AirTunes/150.33\r\nCSeq:", -1);
         send_buffer(fd, seq, -1);
         send_buffer(fd, "\r\n\r\n", -1);
      }
      else if (buffer_prefix(buffer, "ANNOUNCE"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "RTSP/1.0 200 OK\r\nAudio-Jack-Status: connected; type=analog\r\nServer: AirTunes/150.33\r\nCSeq:", -1);
         send_buffer(fd, seq, -1);
         send_buffer(fd, "\r\n\r\n", -1);
      }
      else if (buffer_prefix(buffer, "TEARDOWN"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "RTSP/1.0 200 OK\r\nServer: AirTunes/150.33\r\nCSeq:", -1);
         send_buffer(fd, seq, -1);
         send_buffer(fd, "\r\n\r\n", -1);
      }
      else if (buffer_prefix(buffer, "SETUP"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "RTSP/1.0 200 OK\r\nServer: AirTunes/150.33\r\nAudio-Jack-Status: connected; type=analog\r\nSession: DEADBEEF\r\nTransport: RTP/AVP/UDP;unicast;mode=record;server_port=6009;control_port=6010;timing_port=6011;event_port=49152\r\nCseq:", -1);
         send_buffer(fd, seq, -1);
         send_buffer(fd, "\r\n\r\n", -1);
      }
      else if (buffer_prefix(buffer, "RECORD"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "RTSP/1.0 200 OK\r\nServer: AirTunes/150.33\r\nAudio-Latency: 4410\r\nAudio-Jack-Status: connected; type=analog\r\nCSeq:", -1);
         send_buffer(fd, seq, -1);
         send_buffer(fd, "\r\n\r\n", -1);
      }
      else if (buffer_prefix(buffer, "FLUSH"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "RTSP/1.0 200 OK\r\nServer: AirTunes/150.33\r\nAudio-Latency: 4410\r\nAudio-Jack-Status: connected; type=analog\r\nCSeq:", -1);
         send_buffer(fd, seq, -1);
         send_buffer(fd, "\r\n\r\n", -1);
      }
      else if (buffer_prefix(buffer, "GET_PARAMETER"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "RTSP/1.0 200 OK\r\nServer: AirTunes/150.33\r\nAudio-Jack-Status: connected; type=analog\r\n~volume: 0.000000\r\nCSeq:", -1);
         send_buffer(fd, seq, -1);
         send_buffer(fd, "\r\n\r\n", -1);
      }
      else if (buffer_prefix(buffer, "SET_PARAMETER"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "RTSP/1.0 200 OK\r\nServer: AirTunes/150.33\r\nCSeq:", -1);
         send_buffer(fd, seq, -1);
         send_buffer(fd, "\r\n\r\n", -1);
      }
      else if (buffer_prefix(buffer, "GET /stream.xml"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "HTTP/1.1 200 OK\r\nDate: Wed, 15 Apr 2013 07:42:01 GMT\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: 387\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>height</key><integer>1080</integer><key>overscanned</key><false/><key>refreshRate</key><real>0.016666666666666666</real><key>version</key><string>150.33</string><key>width</key><integer>1920</integer></dict></plist>", -1);
      }
      else if (buffer_prefix(buffer, "GET /server-info"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "HTTP/1.1 200 OK\r\nDate: Wed, 15 Apr 2013 07:42:01 GMT\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: 378\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>deviceid<key><string>58:55:19:82:19:82</string><key>features></key><key>model</key><string>AppleTV3,1</string><key>protovers</key><string>1.0</string><key>srcvers</key><string>150.33</string></dict></plist>", -1);
      }
      else if (buffer_prefix(buffer, "PUT /setProperty"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         // Just ignore it
         send_buffer(fd, "HTTP/1.1 200 OK\r\nDate: Wed, 15 Apr 2013 07:42:01 GMT\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: 222\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>errorCode</key><integer>0</integer></dict></plist>", -1);
      }
      else if (buffer_prefix(buffer, "POST /rate"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         rate = atof(&buffer[17]);
         printf("new rate: %f\n", rate);
         // Just ignore it
         send_buffer(fd, "HTTP/1.1 200 OK\r\nDate: Wed, 15 Apr 2013 07:42:01 GMT\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: 0\r\n\r\n", -1);
      }
      else if (buffer_prefix(buffer, "POST /getProperty"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "HTTP/1.1 200 OK\r\nDate: Wed, 15 Apr 2013 07:42:01 GMT\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: 0\r\n\r\n", -1);
      }
      else if (buffer_prefix(buffer, "GET /scrub"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "HTTP/1.1 200 OK\r\nDate: Wed, 15 Apr 2013 07:42:01 GMT\r\nContent-Type: text/parameters\r\nContent-Length: 25\r\n\r\nduration: 1200\nposition:0", -1);
      }
      else if (buffer_prefix(buffer, "POST /stop"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "HTTP/1.1 200 OK\r\nDate: Wed, 15 Apr 2013 07:42:01 GMT\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: 0\r\n\r\n", -1);
      }

      else if (buffer_prefix(buffer, "POST /play"))
      {
         char seq[8];
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         char* url = &body[18];
         for (int i = 0; i < content_length; i++)
         {
            if (url[i] == '\r' || url[i] == '\n')
            {
               url[i] = 0;
               break;
            }
         }
         printf(">>>>>>>>>>>>> We have been asked to play %s\n", url);   // this is obviously not implemented!
         if (buffer_prefix(url, "mlhls://"))
         {
            printf("Cannot understand mlhls :(\n");
            send_buffer(fd, "HTTP/1.1 500 Garbage URL\r\nDate: Mon, 08 Mar 2013 18:08:25 GMT\r\nContent-Length: 0\r\n\r\n", -1);
         }
         else
         {
            send_buffer(fd, "HTTP/1.1 200 OK\r\nDate: Mon, 08 Mar 2013 18:08:25 GMT\r\nContent-Length: 0\r\n\r\n", -1);
            // Have to parse the URL, open a connection to the server, parse the MOV file to get at the h264 content, and pass that to data_ready
            // at the correct time, all the while updating position, duration, etc.
         }
         free(body);
                  
      }
      else if (buffer_prefix(buffer, "GET /playback-info"))
      {
         char seq[8];
         char info_buffer[2048];
         char header_buffer[512];
         int content_length;
         parse_headers(fd, &content_length, seq);
         sprintf(info_buffer,
                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\">"
                 "<dict>"
                 "   <key>duration</key>"
                 "   <real>%f</real>"
                 "   <key>loadedTimeRanges</key>"
                 "   <array>"
                 "     <dict>"
                 "       <key>duration</key>"
                 "       <real>%f</real>"
                 "       <key>start</key>"
                 "       <real>%f</real>"
                 "     </dict>"
                 "   </array>"
                 "   <key>playbackBufferEmpty</key>"
                 "   <true/>"
                 "   <key>playbackBufferFull</key>"
                 "   <false/>"
                 "   <key>playbackLikelyToKeepUp</key>"
                 "   <true/>"
                 "   <key>position</key>"
                 "   <real>%f</real>"
                 "   <key>rate</key>"
                 "   <real>%f</real>"
                 "   <key>readyToPlay</key>"
                 "   <true/>"
                 "   <key>seekableTimeRanges</key>"
                 "   <array>"
                 "     <dict>"
                 "       <key>duration</key>"
                 "       <real>%f</real>"
                 "       <key>start</key>"
                 "       <real>%f</real>"
                 "     </dict>"
                 "   </array>"
                 " </dict>"
                 "</plist>", duration, duration, 0.0f, position, rate, duration, 0.0f);
         content_length = strlen(info_buffer);
         sprintf(header_buffer, "HTTP/1.1 200 OK\r\nDate: Wed, 15 Apr 2013 07:42:01 GMT\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: %d\r\n\r\n", content_length);
         send_buffer(fd, header_buffer, -1);
         send_buffer(fd, info_buffer, -1);
      }
      else if (buffer_prefix(buffer, "POST /reverse"))
      {
         // might need to spawn a thread here to handle this
         char seq[8] ;
         int content_length;
         parse_headers(fd, &content_length, seq);
         char* body = malloc(content_length);
         read_body(fd, body, content_length);
         free(body);
         send_buffer(fd, "HTTP/1.1 101 Switching Protocols\r\nDate: Thu, 21 Feb 2013 17:33:41 GMT\r\nUpgrade: PTTH/1.0\r\nConnection: Upgrade\r\n\r\n", -1);
         printf("Reverse connection established\n");
      }
      else
      {
         printf("Unexpected request: %s\n", buffer);
         send_buffer(fd, "RTSP/1.0 404 Not Found\r\n\r\n", -1);
         exit_thread(fd, "Unexpected request\n");
      }
   }
   free(buffer);
}

void* http_server(void* port)
{
   struct sockaddr_storage client_addr;
   socklen_t addr_size;
   struct addrinfo hints, *res;
   int sockfd;
   int yes = 1;
   
   memset(&hints, 0, sizeof hints);
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_PASSIVE;
   getaddrinfo(NULL, (char*)port, &hints, &res);
   printf("Binding port %s\n", port);
   sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
   assert(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == 0);
   if (bind(sockfd, res->ai_addr, res->ai_addrlen) != 0)
   {
      printf("Could not bind on %s\n", port);
      exit(0);
   }
   assert(listen(sockfd, 5) == 0);
   printf("Listening on port %s\n", port);
   while(1)
   {
      pthread_attr_t attr;
      pthread_t client;
      int* client_fd = malloc(sizeof(int));
      addr_size = sizeof(client_addr);
      *client_fd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_size);
      printf("Client connected on port %s\n", port);
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
      pthread_create(&client, &attr, http_worker, client_fd);
   }
}

//{"srcvers=150.33", "model=AppleTV3,1", "features=0x100029ff", "deviceid=58:55:19:82:19:82", "vv=1", "rhd=1.05.2", "pw=0"},
//{"da=true", "vs=150.33", "md=0,1,2", "txtvers=1", "vn=65537", "pw=false", "sr=44100", "ss=16", "ch=2", "cn=0,1,2,3", "et=0,1,3", "ek=1", "sv=false", "sm=false", "tp=UDP", "am=AppleTV3,1", "vv=1", "txtvers=1", "sf=0x4", "rhd=1.05.2"}};   

#include <dns_sd.h>
void register_zeroconf()
{
   DNSServiceRef client;
   DNSServiceFlags flags = 0;
   unsigned char txt1[] = {0x0e,0x73,0x72,0x63,0x76,0x65,0x72,0x73,0x3d,0x31,0x35,0x30,0x2e,0x33,0x33,0x10,0x6d,0x6f,0x64,0x65,0x6c,0x3d,0x41,0x70,0x70,0x6c,0x65,0x54,0x56,0x33,0x2c,0x31,0x13,0x66,0x65,0x61,0x74,0x75,0x72,0x65,0x73,0x3d,0x30,0x78,0x31,0x30,0x30,0x30,0x32,0x39,0x66,0x66,0x1a,0x64,0x65,0x76,0x69,0x63,0x65,0x69,0x64,0x3d,0x35,0x38,0x3a,0x35,0x35,0x3a,0x31,0x39,0x3a,0x38,0x32,0x3a,0x31,0x39,0x3a,0x38,0x32,0x04,0x76,0x76,0x3d,0x31,0x0a,0x72,0x68,0x64,0x3d,0x31,0x2e,0x30,0x35,0x2e,0x32,0x04,0x70,0x77,0x3d,0x30};
   unsigned char txt2[] = {0x07,0x64,0x61,0x3d,0x74,0x72,0x75,0x65,0x09,0x76,0x73,0x3d,0x31,0x35,0x30,0x2e,0x33,0x33,0x08,0x6d,0x64,0x3d,0x30,0x2c,0x31,0x2c,0x32,0x09,0x74,0x78,0x74,0x76,0x65,0x72,0x73,0x3d,0x31,0x08,0x76,0x6e,0x3d,0x36,0x35,0x35,0x33,0x37,0x08,0x70,0x77,0x3d,0x66,0x61,0x6c,0x73,0x65,0x08,0x73,0x72,0x3d,0x34,0x34,0x31,0x30,0x30,0x05,0x73,0x73,0x3d,0x31,0x36,0x04,0x63,0x68,0x3d,0x32,0x0a,0x63,0x6e,0x3d,0x30,0x2c,0x31,0x2c,0x32,0x2c,0x33,0x08,0x65,0x74,0x3d,0x30,0x2c,0x31,0x2c,0x33,0x04,0x65,0x6b,0x3d,0x31,0x08,0x73,0x76,0x3d,0x66,0x61,0x6c,0x73,0x65,0x08,0x73,0x6d,0x3d,0x66,0x61,0x6c,0x73,0x65,0x06,0x74,0x70,0x3d,0x55,0x44,0x50,0x0d,0x61,0x6d,0x3d,0x41,0x70,0x70,0x6c,0x65,0x54,0x56,0x33,0x2c,0x31,0x04,0x76,0x76,0x3d,0x31,0x09,0x74,0x78,0x74,0x76,0x65,0x72,0x73,0x3d,0x31,0x06,0x73,0x66,0x3d,0x30,0x78,0x34,0x0a,0x72,0x68,0x64,0x3d,0x31,0x2e,0x30,0x35,0x2e,0x32};
   unsigned char* txt[2] = {txt1, txt2};                   
   int txtlen[2] = {100, 172};
   char* service[2] = {"PlayFair", "585519821982@PlayFair"};
   char* type[2] = {"_airplay._tcp", "_raop._tcp"};
   int port[2] = {htons(7000), htons(49152)};
   for (int i = 0; i < 2; i++)
      assert(DNSServiceRegister(&client,
                                flags,
                                0,
                                service[i],
                                type[i],
                                "local",
                                NULL, 
                                port[i],
                                txtlen[i],
                                txt[i],
                                NULL,
                                NULL) == kDNSServiceErr_NoError);
}

int main()
{
   pthread_t thread[4];
   void* rval;
#ifdef HAVE_OPENMAX
   bcm_host_init();
#endif
   register_zeroconf();
      
   char* port[] = {"7000", "7100", "6010", "49152"};
   int i;
   for (i = 0; i < 4; i++)
      pthread_create(&thread[i], NULL, http_server, port[i]);
   for (i = 0; i < 4; i++)
      pthread_join(thread[i], rval);
   return 0;
}
