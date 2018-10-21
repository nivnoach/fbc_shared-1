/*
 * 'main.c' - RADIUS over HTTP/2 reference implementation
 *
 * Copyright (c) 2018-present, Facebook, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include "config_parser.h"
#include "radius_proxy.h"

int debug_verbosity = 0;

static struct option arg_options[] = {{"help", no_argument, 0, 'h'},
                                      {"debug", no_argument, 0, 'd'},
                                      {"config", required_argument, 0, 'c'},
                                      {0, 0, 0, 0}};

void print_usage() {
  char* config_file_desc = get_config_opts_desc("\t\t");
  if (!config_file_desc)
    return;
  printf("Usage:\n");

  printf("\t[--help|-h]\t\t\tPrint this message\n");
  printf("\t[--debug|-d]\t\t\tShow debug prints\n");
  printf("\t[--config|-c] CONFIG_FILE\tConfiguration file\n");
  printf("\n\tConfiguration file format:\n%s", config_file_desc);
  free(config_file_desc);
}

#define MAX_CONFIG_FILENAME 200
int main(int argc, char** argv) {
  char conf_fname[MAX_CONFIG_FILENAME] = {0};
  struct ev_loop* loop;
  radius_proxy_t* proxy;
  int option_index = 0;
  int opt;
  int rc = 0;

  hostname_init();
  prof * init_prof = prof_start("SERVICE_INIT", RADIUS_CODE_NONE);

  while ((opt = getopt_long(argc, argv, "hdc:", arg_options, &option_index)) !=
         -1) {
    switch (opt) {
      case 'd':
        debug_verbosity = 1;
        break;
      case 'c':
        if (strlen(optarg) >= MAX_CONFIG_FILENAME) {
          RAD_PROXY_LOG_ERR("Very long file name");
          goto out_err;
        }
        strcpy(conf_fname, optarg);
        break;
      case '?':
      case 'h':
        print_usage();
      default:
        goto out_err;
    }
  }

  if (!strlen(conf_fname)) {
    RAD_PROXY_LOG_ERR("Config file argument is mandatory");
    print_usage();
    goto out_err;
  }

  rc = process_config_file(conf_fname);
  if (rc) {
    print_usage();
    goto out_err;
  }

  // Initialize and loop
  loop = ev_loop_new(EVFLAG_AUTO);
  proxy = init_radius_proxy(loop);

  prof_end_ok(init_prof);

  ev_loop(loop, 0); // Start event loop

  // Deallocate resources
  free_radius_proxy(proxy);
  ev_loop_destroy(loop);
  curl_global_cleanup();

  return 0;

out_err:
  prof_end_err(init_prof, rc);
  return -1;
}
