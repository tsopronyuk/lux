#ifndef RPCBLOCKCHAIN_H
#define RPCBLOCKCHAIN_H

class CBlock;
class CBlockIndex;
class UniValue;

/** Callback for when block tip changed. */
void RPCNotifyBlockChange(bool ibd, const CBlockIndex *);

#endif // RPCBLOCKCHAIN_H
