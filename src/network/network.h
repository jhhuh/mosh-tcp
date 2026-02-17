/*
    Mosh: the mobile shell
    Copyright 2012 Keith Winstein

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations including
    the two.

    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do
    so, delete this exception statement from your version. If you delete
    this exception statement from all source files in the program, then
    also delete it here.
*/

#ifndef NETWORK_HPP
#define NETWORK_HPP

#include <stdint.h>
#include <deque>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include <math.h>
#include <vector>
#include <assert.h>
#include <exception>
#include <string.h>

#include "crypto.h"

using namespace Crypto;

namespace Network {
  static const unsigned int MOSH_PROTOCOL_VERSION = 2; /* bumped for echo-ack */

  uint64_t timestamp( void );
  uint16_t timestamp16( void );
  uint16_t timestamp_diff( uint16_t tsnew, uint16_t tsold );

  class NetworkException : public std::exception {
  public:
    string function;
    int the_errno;
  private:
    string my_what;
  public:
    NetworkException( string s_function="<none>", int s_errno=0)
      : function( s_function ), the_errno( s_errno ),
        my_what(function + ": " + strerror(the_errno)) {}
    const char *what() const throw () { return my_what.c_str(); }
    ~NetworkException() throw () {}
  };

  enum Direction {
    TO_SERVER = 0,
    TO_CLIENT = 1
  };

  class Packet {
  public:
    const uint64_t seq;
    Direction direction;
    uint16_t timestamp, timestamp_reply;
    string payload;
    
    Packet( Direction s_direction,
	    uint16_t s_timestamp, uint16_t s_timestamp_reply, const string & s_payload )
      : seq( Crypto::unique() ), direction( s_direction ),
	timestamp( s_timestamp ), timestamp_reply( s_timestamp_reply ), payload( s_payload )
    {}
    
    Packet( const Message & message );
    
    Message toMessage( void );
  };

  union Addr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr_storage ss;
  };

  class Connection {
  private:
    /* TCP framing: [4-byte big-endian length][payload] */
    static const int TCP_FRAME_HEADER_LEN = 4;

    /* Application datagram MTU. TCP handles segmentation, so use a large value. */
    static const int DEFAULT_SEND_MTU = 16384;

    static const uint64_t MIN_RTO = 50; /* ms */
    static const uint64_t MAX_RTO = 1000; /* ms */

    static const int PORT_RANGE_LOW  = 60001;
    static const int PORT_RANGE_HIGH = 60999;

    static const unsigned int SERVER_ASSOCIATION_TIMEOUT = 40000;

    bool try_bind( const char *addr, int port_low, int port_high );

    class Socket
    {
    private:
      int _fd;

    public:
      int fd( void ) const { return _fd; }
      Socket( int family );
      ~Socket();

      Socket( const Socket & other );
      Socket & operator=( const Socket & other );
    };

    std::deque< Socket > socks;
    bool has_remote_addr;
    Addr remote_addr;
    socklen_t remote_addr_len;

    bool server;
    bool accepted; /* server: has accepted a TCP connection */

    int MTU; /* application datagram MTU */

    string tcp_recv_buf; /* accumulates partial TCP frames */

    Base64Key key;
    Session session;

    Direction direction;
    uint16_t saved_timestamp;
    uint64_t saved_timestamp_received_at;
    uint64_t expected_receiver_seq;

    uint64_t last_heard;
    uint64_t last_roundtrip_success; /* transport layer needs to tell us this */

    bool RTT_hit;
    double SRTT;
    double RTTVAR;

    /* Error from send(). */
    string send_error;

    Packet new_packet( const string &s_payload );

    int sock( void ) const { assert( !socks.empty() ); return socks.back().fd(); }

    string recv_one( int sock_to_recv );

  public:
    /* Network transport overhead. */
    static const int ADDED_BYTES = 8 /* seqno/nonce */ + 4 /* timestamps */;

    Connection( const char *desired_ip, const char *desired_port ); /* server */
    Connection( const char *key_str, const char *ip, const char *port ); /* client */

    void send( const string & s );
    string recv( void );
    const std::vector< int > fds( void ) const;
    int get_MTU( void ) const { return MTU; }

    std::string port( void ) const;
    string get_key( void ) const { return key.printable_key(); }
    bool get_has_remote_addr( void ) const { return has_remote_addr; }

    uint64_t timeout( void ) const;
    double get_SRTT( void ) const { return SRTT; }

    const Addr &get_remote_addr( void ) const { return remote_addr; }
    socklen_t get_remote_addr_len( void ) const { return remote_addr_len; }

    string &get_send_error( void )
    {
      return send_error;
    }

    void set_last_roundtrip_success( uint64_t s_success ) { last_roundtrip_success = s_success; }

    static bool parse_portrange( const char * desired_port_range, int & desired_port_low, int & desired_port_high );
  };
}

#endif
