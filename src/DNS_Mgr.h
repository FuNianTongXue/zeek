// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <ares.h>
#include <list>
#include <map>
#include <queue>
#include <utility>

#include "zeek/EventHandler.h"
#include "zeek/IPAddr.h"
#include "zeek/List.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/util.h"

namespace zeek
	{

class EventHandler;
class RecordType;
class Val;
class ListVal;
class TableVal;

template <class T> class IntrusivePtr;
using ValPtr = IntrusivePtr<Val>;
using ListValPtr = IntrusivePtr<ListVal>;
using TableValPtr = IntrusivePtr<TableVal>;

	} // namespace zeek

namespace zeek::detail
	{

class DNS_Mgr_Request;
using DNS_mgr_request_list = PList<DNS_Mgr_Request>;

class DNS_Mapping;

enum DNS_MgrMode
	{
	DNS_PRIME, // used to prime the cache
	DNS_FORCE, // internal error if cache miss
	DNS_DEFAULT, // lookup names as they're requested
	DNS_FAKE, // don't look up names, just return dummy results
	};

// Number of seconds we'll wait for a reply.
constexpr int DNS_TIMEOUT = 5;

class DNS_Mgr final : public iosource::IOSource
	{
public:
	explicit DNS_Mgr(DNS_MgrMode mode);
	~DNS_Mgr() override;

	void InitPostScript();
	void Flush();

	/**
	 * Looks up the address(es) of a given host and returns a set of addr.
	 * This is a synchronous method and will block until results are ready.
	 *
	 * @param host The host name to look up an address for.
	 * @return A set of addresses.
	 */
	TableValPtr LookupHost(const char* host);

	/**
	 * Looks up the hostname of a given address. This is a synchronous method
	 * and will block until results are ready.
	 *
	 * @param host The addr to lookup a hostname for.
	 * @return The hostname.
	 */
	ValPtr LookupAddr(const IPAddr& addr);

	// Define the directory where to store the data.
	void SetDir(const char* arg_dir) { dir = arg_dir; }

	void Resolve();
	bool Save();

	const char* LookupAddrInCache(const IPAddr& addr);
	TableValPtr LookupNameInCache(const std::string& name);
	const char* LookupTextInCache(const std::string& name);

	// Support for async lookups.
	class LookupCallback
		{
	public:
		virtual ~LookupCallback() = default;

		virtual void Resolved(const char* name){};
		virtual void Resolved(TableVal* addrs){};
		virtual void Timeout() = 0;
		};

	void AsyncLookupAddr(const IPAddr& host, LookupCallback* callback);
	void AsyncLookupName(const std::string& name, LookupCallback* callback);
	void AsyncLookupNameText(const std::string& name, LookupCallback* callback);

	struct Stats
		{
		unsigned long requests; // These count only async requests.
		unsigned long successful;
		unsigned long failed;
		unsigned long pending;
		unsigned long cached_hosts;
		unsigned long cached_addresses;
		unsigned long cached_texts;
		};

	void GetStats(Stats* stats);

	void AddResult(DNS_Mgr_Request* dr, struct hostent* h, uint32_t ttl);

	static TableValPtr empty_addr_set();

protected:
	friend class LookupCallback;
	friend class DNS_Mgr_Request;

	void Event(EventHandlerPtr e, DNS_Mapping* dm);
	void Event(EventHandlerPtr e, DNS_Mapping* dm, ListValPtr l1, ListValPtr l2);
	void Event(EventHandlerPtr e, DNS_Mapping* old_dm, DNS_Mapping* new_dm);

	ValPtr BuildMappingVal(DNS_Mapping* dm);

	void CompareMappings(DNS_Mapping* prev_dm, DNS_Mapping* new_dm);
	ListValPtr AddrListDelta(ListVal* al1, ListVal* al2);
	void DumpAddrList(FILE* f, ListVal* al);

	using HostMap = std::map<std::string, std::pair<DNS_Mapping*, DNS_Mapping*>>;
	using AddrMap = std::map<IPAddr, DNS_Mapping*>;
	using TextMap = std::map<std::string, DNS_Mapping*>;
	void LoadCache(const std::string& path);
	void Save(FILE* f, const AddrMap& m);
	void Save(FILE* f, const HostMap& m);

	// Issue as many queued async requests as slots are available.
	void IssueAsyncRequests();

	// Finish the request if we have a result.  If not, time it out if
	// requested.
	void CheckAsyncAddrRequest(const IPAddr& addr, bool timeout);
	void CheckAsyncHostRequest(const char* host, bool timeout);
	void CheckAsyncTextRequest(const char* host, bool timeout);

	// IOSource interface.
	void Process() override;
	void InitSource() override;
	const char* Tag() override { return "DNS_Mgr"; }
	double GetNextTimeout() override;

	DNS_MgrMode mode;

	HostMap host_mappings;
	AddrMap addr_mappings;
	TextMap text_mappings;

	DNS_mgr_request_list requests;

	std::string cache_name;
	std::string dir; // directory in which cache_name resides

	bool did_init = false;
	int asyncs_pending = 0;

	RecordTypePtr dm_rec;

	ares_channel channel;
	bool ipv6_resolver = false;

	using CallbackList = std::list<LookupCallback*>;

	struct AsyncRequest
		{
		double time = 0.0;
		IPAddr host;
		std::string name;
		CallbackList callbacks;
		bool is_txt = false;
		bool processed = false;

		bool IsAddrReq() const { return name.empty(); }

		void Resolved(const char* name)
			{
			for ( CallbackList::iterator i = callbacks.begin(); i != callbacks.end(); ++i )
				{
				(*i)->Resolved(name);
				delete *i;
				}
			callbacks.clear();
			processed = true;
			}

		void Resolved(TableVal* addrs)
			{
			for ( CallbackList::iterator i = callbacks.begin(); i != callbacks.end(); ++i )
				{
				(*i)->Resolved(addrs);
				delete *i;
				}
			callbacks.clear();
			processed = true;
			}

		void Timeout()
			{
			for ( CallbackList::iterator i = callbacks.begin(); i != callbacks.end(); ++i )
				{
				(*i)->Timeout();
				delete *i;
				}
			callbacks.clear();
			processed = true;
			}
		};

	using AsyncRequestAddrMap = std::map<IPAddr, AsyncRequest*>;
	AsyncRequestAddrMap asyncs_addrs;

	using AsyncRequestNameMap = std::map<std::string, AsyncRequest*>;
	AsyncRequestNameMap asyncs_names;

	using AsyncRequestTextMap = std::map<std::string, AsyncRequest*>;
	AsyncRequestTextMap asyncs_texts;

	using QueuedList = std::list<AsyncRequest*>;
	QueuedList asyncs_queued;

	struct AsyncRequestCompare
		{
		bool operator()(const AsyncRequest* a, const AsyncRequest* b) { return a->time > b->time; }
		};

	using TimeoutQueue =
		std::priority_queue<AsyncRequest*, std::vector<AsyncRequest*>, AsyncRequestCompare>;
	TimeoutQueue asyncs_timeouts;

	unsigned long num_requests;
	unsigned long successful;
	unsigned long failed;
	};

extern DNS_Mgr* dns_mgr;

	} // namespace zeek::detail
