/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h> 


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/



void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

/* Since I saw that you did seperate ip packet to router and ip packet
  to others, i created those two functions to handle different behaviors.
  Feel free to remove those if you have already doen that*/
/*void Handle_IP_To_Router(struct sr_instance* sr,
                  uint8_t* packet
                  unsigned int len,
                  struct sr_if* iface){
    /* Get all header first 
    sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_header = ()
 }

 void Handle_IP_TO_Others(struct sr_instance* sr,
                  uint8_t* packet,
                  unsigned int len,
                  struct sr_if* iface){

 }*/


void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("\n\nReceived packet of length %d \n",len);
  printf("Receiving interface %s \n",interface);
 /* print_hdr_eth(packet);*/

  /* Sanity checks */

  if (len > 1514)
  {
    fprintf(stderr, "Error: EthHeader 1514 check not met");
    return;
  }  

  if (len < sizeof(sr_ethernet_hdr_t)) 
  {
    fprintf(stderr, "Error: Packet size < EthHeader size");
    return;
  } 

  /* IP/ICMP/ARP */
  uint16_t ether_type = ethertype(packet); 
  printf("Receiving header type %x \n\n",ether_type);

  switch (ether_type)
  {
    /* IP */
    case 0x0800: 
        process_ether_type_ip(sr, packet, len, interface);
        break;

    /* ARP */
    case 0x0806:
        process_ether_type_arp(sr, packet, len, interface);
        break;

    /* Garbage ethernet type */
    default:
        fprintf(stderr, "Error: Garbage ether_type %d", ether_type);
        return;
  }
return;   
}

void process_ether_type_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  printf("Packet found to be type IP!\n\n");

  printf("This is what I received!\n\n");
  print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)(packet);

  /* Create IP header struct for further processing */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Checksum computation */
  ip_header->ip_sum = 0;

  /* Decrement TTL and recompute checksum */
  ip_header->ip_ttl--;
  ip_header->ip_sum = cksum((const void*)ip_header, sizeof(sr_ip_hdr_t));  

  struct sr_if* pkt_interface = sr_get_interface(sr, interface);

  /* IP packet destined for router's interface - NO GO */
  /* Processing only for ICMP echo request-reply otherwise no go */
  
  if (pkt_interface!=0) /* Interface record exists */
  { 
    if (ip_header->ip_p == ip_protocol_icmp) /* PING */
    {
      printf("\n\nRouter Received ICMP !\n");

      /* Create ICMP Packet */
      sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      /* Process ICMP message */
      if (icmp_header->icmp_type == 8) /* PING */
      {
          printf("\nICMP processing being done.\n\n");

          /* Allocate memory */
          uint8_t* send_packet = (uint8_t *)malloc(len);

          /* Same content as packet */
          memcpy(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

          /* ICMP header */
          sr_icmp_hdr_t* new_icmp = (sr_icmp_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          new_icmp->icmp_type = 0;
          new_icmp->icmp_code = 0;
          new_icmp->icmp_sum = cksum(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), len - sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          /* Ethernet header */
          sr_ethernet_hdr_t *new_ethhdr = (sr_ethernet_hdr_t *) send_packet;
          memcpy(new_ethhdr->ether_dhost, eth_header->ether_shost, 6);
          memcpy(new_ethhdr->ether_shost, pkt_interface->addr, 6);

          new_ethhdr->ether_type = ntohs(0x0800);

          /* IP header */
          sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t));
          new_iphdr->ip_len = ntohs(len - sizeof(sr_ethernet_hdr_t));
          new_iphdr->ip_ttl = 64; /* 64 */
          new_iphdr->ip_v = 4;
          new_iphdr->ip_hl = 5;
          new_iphdr->ip_dst = ip_header->ip_src;
          new_iphdr->ip_src = pkt_interface->ip;
          new_iphdr->ip_p = 0x0001;
          new_iphdr->ip_sum = 0;
          new_iphdr->ip_sum = cksum(send_packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));


          printf("\nThis is what I am sending!\n\n");

          /* Send the packet */
          print_hdrs(send_packet, len);
          sr_send_packet(sr, send_packet, len, interface);

          /*sr_send_packet(sr, send_packet, len, interface);*/

          free (send_packet);

          return;
      }
      else 
      {
        /* Drop DA packet*/
        printf("Non-PING ICMP packet sent to Router's interface. Dropping.\n");
      }
    }
    /*receive a TCP/UDP packet, send ICMP port unreachable back*/
    else if(ip_header->ip_p == ip_protocol_tcp || ip_header->ip_p == ip_protocol_udp){
        printf("Receiving TCP/UDP packet\n");

        size_t tulen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        uint8_t* send_packet = malloc(tulen);
        sr_ethernet_hdr_t* new_ether_header = (sr_ethernet_hdr_t*)send_packet;
        sr_ip_hdr_t* new_ip_header = (sr_ip_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t* new_icmp_header = (sr_icmp_t3_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /*write ethernet header*/
        memcpy(new_ether_header->ether_dhost, eth_header->ether_shost, 6);
        memcpy(new_ether_header->ether_shost, pkt_interface->addr, 6);
        new_ether_header->ether_type = htons(0x0800);

        /*write ip header*/
        new_ip_header->ip_hl = 5;
        new_ip_header->ip_v = 4;
        new_ip_header->ip_tos = ip_header->ip_tos;
        new_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        new_ip_header->ip_id = ip_header->ip_id;
        new_ip_header->ip_off = 0;
        new_ip_header->ip_ttl = 64;
        new_ip_header->ip_p = ip_protocol_icmp;
        new_ip_header->ip_sum = 0;
        new_ip_header->ip_src = pkt_interface->ip;
        new_ip_header->ip_dst = ip_header->ip_src;
        new_ip_header->ip_sum = cksum(new_ip_header, sizeof(sr_ip_hdr_t));

        /*write icmp header*/
        new_icmp_header->icmp_type = 3;
        new_icmp_header->icmp_code = 3;
        new_icmp_header->icmp_sum = 0;
        new_icmp_header->next_mtu = htons(512);
        memcpy(new_icmp_header->data, ip_header, sizeof(sr_ip_hdr_t));
        memcpy(new_icmp_header->data + sizeof(sr_ip_hdr_t), send_packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), 8);
        new_icmp_header->icmp_sum = cksum(send_packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), sizeof(sr_icmp_t3_hdr_t));

        printf("\nThis is what I am sending!\n\n");
        print_hdrs(send_packet, tulen);

        /*send packet*/
        sr_send_packet(sr, send_packet, tulen, interface);
        free(send_packet);
        return;
    } 
    else{
      printf("Unknown IP protocol number, Drop packet\n");
    }    
  }

  else 
  {
    /* Forward the Packet  */
    printf("Forwarding Packet\n");

/*
    -------------------------------------------

    # When sending packet to next_hop_ip
    entry = arpcache_lookup(next_hop_ip)

    if entry:
        use next_hop_ip->mac mapping in entry to send the packet
        free entry
    else:
        req = arpcache_queuereq(next_hop_ip, packet, len)
        handle_arpreq(req)

     ------------------------------------------
*/       
 
/* 
    struct sr_rt* rt_entry = table_lookup(sr, ip_header->ip_dst);
    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), rt_entry->gw.s_addr); 

    if (arp_entry!=NULL) {
      printf("ARP Cache Hit\n");

      sr_ethernet_hdr_t* send_packet = (sr_ethernet_hdr_t *)(packet);
      struct sr_if* dest_interface = sr_get_interface(sr, rt_entry->interface);

      memcpy(send_packet->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      memcpy(send_packet->ether_shost, dest_interface->addr, ETHER_ADDR_LEN);

      
      sr_send_packet(sr, packet, len, rt_entry->interface);     
      free(arp_entry);
    } 
    else 
    {
      printf("ARP Cache Miss\n");
      struct sr_arpreq* resolve = sr_arpcache_queuereq(&(sr->cache), rt_entry->gw.s_addr, packet, len, rt_entry->interface);
      
      sr_handle_arpreq(sr, resolve);
    }    
    printf("Packet forwarded\n");
  */  
  }                  
}


void process_ether_type_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* iface/* lent */)
{

/* Router receives an ARP packet  */
  assert(sr);
  assert(packet);
  assert(iface);


  printf("Packet found to type ARP! \n\n");

  /* Create ARP Header and find interface */
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));


  struct sr_if* interface = sr_find_interface(sr, arp_header->ar_tip);
  unsigned short op_code = ntohs(arp_header->ar_op);

/*
  if (op_code == 0x0002) { 
    printf("Processing ARP Reply\n");


    struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);



    if (req !=NULL)
    {
      printf("Yes, Packets exist !\n\n\n");
      struct sr_packet* queue_packets = req->packets;
      while (queue_packets!=NULL)
      {
        sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t *)(queue_packets->buf);
        memcpy(ethernet_hdr->ether_dhost, arp_header->ar_sha, 6);
        memcpy(ethernet_hdr->ether_shost, interface->addr, 6);
        sr_send_packet(sr, queue_packets->buf, queue_packets->len, interface->name);        
        queue_packets=queue_packets->next;
      }
    }
  } 
 */

  if (op_code == 0x0001) { /* Process ARP Request */
    printf("\nProcessing ARP Request\n");

    sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)(packet);
    memcpy(arp_header->ar_tha, arp_header->ar_sha, 6);
    memcpy(arp_header->ar_sha, interface->addr, 6);
    memcpy(ethernet_hdr->ether_dhost, arp_header->ar_tha, 6);
    memcpy(ethernet_hdr->ether_shost, arp_header->ar_sha, 6);
    arp_header->ar_tip = arp_header->ar_sip;
    arp_header->ar_sip = interface->ip;
    arp_header->ar_op = htons(0x0002);

    printf("Sending out ARP Reply\n\n");
    printf("This is what I sent\n\n");

    print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

    sr_send_packet(sr, packet, len, iface);
  }
/*  free(rt_entry); */
}


void sr_handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req) {

  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0) 
  {
      struct sr_rt* rt_entry = table_lookup(sr, req->ip);      
      struct sr_if* iface = sr_get_interface(sr, rt_entry->interface);

      uint8_t* packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
      sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) packet;
      ether_hdr->ether_type = htons(0x0806);
      memset(ether_hdr->ether_dhost, 0xFF, 6);
      memcpy(ether_hdr->ether_shost, iface->addr, 6);


      sr_arp_hdr_t* arp_frame = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
      arp_frame->ar_hrd = htons(0x0001);
      arp_frame->ar_pro = htons(0x0800);
      arp_frame->ar_hln = 6;
      arp_frame->ar_pln = 4;
      arp_frame->ar_op = htons(0x0001);
      arp_frame->ar_sip = iface->ip;
      memcpy(arp_frame->ar_sha, iface->addr, 6);
      arp_frame->ar_tip = req->ip;
      memset(arp_frame->ar_tha, 0xFF, 6);


      printf("Sending ARP Request\n");
      sr_send_packet(sr, packet, (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)), iface->name);
      free(packet);
      req->sent = now;
      req->times_sent++;
  }
}


struct sr_rt* table_lookup(struct sr_instance* sr, uint32_t ip_dst) 
{
  assert(sr);
  struct sr_rt* query = 0;
  struct sr_rt* table_iterator = sr->routing_table;
  printf("NEH ?!!!!\n");

  while (table_iterator) {
    
    if (((ip_dst & (table_iterator->mask).s_addr) == ((table_iterator->dest).s_addr & (table_iterator->mask).s_addr))) 
    {
    query = table_iterator;
    printf("NEH ?!\n");
    }
    table_iterator = table_iterator->next;
  }

  return query;
}

struct sr_if* sr_find_interface(struct sr_instance* sr, uint32_t ip_dst) 
{
    assert(sr);
    struct sr_if* if_entry = sr->if_list;

    while (if_entry) {
        /* Check for matching IP */
        if (ip_dst == if_entry->ip) {
            /* Interface found */
            return if_entry;
        }
        if_entry = if_entry->next;
    }
    return NULL;
} /* -- sr_find_interface -- */