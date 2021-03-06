/***************************************************************************
 * 
 * Copyright (c) 2016 zkdnfcf, Inc. All Rights Reserved
 * $Id$ 
 * 
 **************************************************************************/
 
 /**
 * @file hash.h
 * @author zk(zkdnfc@163.com)
 * @date 2016/05/31 18:26:01
 * @version $Revision$ 
 * @brief 
 *  
 **/
#ifndef _MAP_H
#define _MAP_H

#include "rbtree.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct map {
    struct rb_node node;
    char *key;
    void *val;
};

typedef struct map map_t;
typedef struct rb_root root_t;
typedef struct rb_node rb_node_t;

static map_t *map_get(root_t *root, const char *str) {
   rb_node_t *node = root->rb_node; 
   while (node) {
        map_t *data = container_of(node, map_t, node);

        //compare between the key with the keys in map
        int cmp = strcmp(str, data->key);
        if (cmp < 0) {
            node = node->rb_left;
        }else if (cmp > 0) {
            node = node->rb_right;
        }else {
            return data;
        }
   }
   return NULL;
}

static int map_put(root_t *root, const char* key, void* val) {
    map_t *data = (map_t*)malloc(sizeof(map_t));
    bzero(data, sizeof(map_t));
    data->key = (char*)malloc(strlen(key));
    bzero(data->key, strlen(key));
    strcpy(data->key, key);
    data->val = val;

    rb_node_t **new_node = &(root->rb_node), *parent = NULL;
    while (*new_node) {
        map_t *this_node = container_of(*new_node, map_t, node);
        int result = strcmp(key, this_node->key);
        parent = *new_node;

        if (result < 0) {
            new_node = &((*new_node)->rb_left);
        }else if (result > 0) {
            new_node = &((*new_node)->rb_right);
        }else {
            return 0;
        }
    }

    rb_link_node(&data->node, parent, new_node);
    rb_insert_color(&data->node, root);

    return 1;
}

static map_t *map_first(root_t *tree) {
    rb_node_t *node = rb_first(tree);
    return (rb_entry(node, map_t, node));
}

static map_t *map_next(rb_node_t *node) {
    rb_node_t *next =  rb_next(node);
    return rb_entry(next, map_t, node);
}

static void map_free(map_t *node){
    if (node != NULL) {
        if (node->key != NULL) {
            free(node->key);
            node->key = NULL;
            free(node->val);
            node->val = NULL;
    }
        free(node);
        node = NULL;
    }
}

static int map_delete(root_t *root, map_t *node) {
    rb_erase(&node->node, root);
    map_free(node);
}

#endif  //_MAP_H

/* vim: set ts=4 sw=4 sts=4 tw=100 */
