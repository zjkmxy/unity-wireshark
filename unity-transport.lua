-- inspect.lua (https://github.com/kikito/inspect.lua) can be used for debugging.
-- See more at http://stackoverflow.com/q/15175859/2150331
-- local inspect = require('inspect')

-- Unity protocol
unity = Proto("Unity", "Unity Transport")


local msgTypeNames = {
  "ConnectionApprovedMessage",
  "ConnectionRequestMessage",
  "ChangeOwnershipMessage",
  "ClientConnectedMessage",
  "ClientDisconnectedMessage",
  "CreateObjectMessage",
  "DestroyObjectMessage",
  -- "DisconnectReasonMessage",
  "NamedMessage",
  "NetworkVariableDeltaMessage",
  "ParentSyncMessage",
  "ProxyMessage",
  "RpcMessages",
  "SceneEventMessage",
  "ServerLogMessage",
  "TimeSyncMessage",
  "UnnamedMessage"
}

local function parseBitPackedUint(buffer)
  local nBytes = buffer(0, 1):le_uint() % 8
  local value = (buffer(0, nBytes):le_uint() - nBytes) / 8
  return value, nBytes
end

local function parseMessage(buffer, tree)
  if buffer(0, 1):le_uint() == 0 then
    return 0
  end
  local msgType, nLen1 = parseBitPackedUint(buffer)

  if msgType < #msgTypeNames then
    tree:add(buffer(0, nLen1), "Message Type: " .. msgTypeNames[msgType + 1])
  else
    tree:add(buffer(0, nLen1), "Message Type: " .. msgType)
  end

  if buffer(nLen1, 1):le_uint() == 0 then
    return 0
  end
  local msgSize, nLen2 = parseBitPackedUint(buffer(nLen1))
  tree:add(buffer(nLen1, nLen2), "Message Size: " .. msgSize)
  tree:add(buffer(nLen1 + nLen2, msgSize), "Message Value")
  return nLen1 + nLen2 + msgSize
end

local function parseBlock(buffer, tree)
  tree:add(buffer(0, 2), "Magic (0x1160): " .. buffer(0, 2):bytes():tohex())
  if buffer(0, 2):le_uint() ~= 0x1160 then
    return
  end
  local batchCount = buffer(2, 2):le_uint()
  tree:add(buffer(2, 2), "BatchCount: " .. batchCount)
  local batchSize = buffer(4, 4):le_uint() - 12
  tree:add(buffer(4, 4), "BatchSize 12+ " .. batchSize)
  local batchHash = buffer(8, 4):le_uint()
  tree:add(buffer(8, 4), "BatchHash: " .. batchHash)

  local subtree = tree:add(buffer(12), "Batch buffer")
  subtree:add(buffer(12, 4), "Mysterious 4 bytes")

  local offset = 16
  for i = 1, batchCount, 1 do
    local msgLen = parseMessage(buffer(offset), subtree)
    if msgLen == 0 then
      break
    end
    offset = offset + msgLen
  end
end

function unity.dissector(buffer, pinfo, tree)
  local Signature1 = ProtoField.uint16("unity.sig0402", "Only consider 0402", base.HEX)
  -- Only parse packets starting with 0402
  if (buffer(0, 2):uint() ~= 1026) then
    return 0
  end

  pinfo.cols.protocol = "Unity"
  local subtree = tree:add(unity, buffer(), "Unity Transport data")
  subtree:add(buffer(0, 2), "Signature: " .. buffer(0, 2):uint())

  local offset = 27
  subtree:add(buffer(2, offset - 2), "Unknown")
  while offset + 3 < buffer:len() do
    local blockLen = buffer(offset, 4):le_uint()
    offset = offset + 4
    local block = buffer(offset, blockLen)
    local blockTree = subtree:add(block, "Netcode Message Batch")
    offset = offset + blockLen

    parseBlock(block, blockTree)
  end
end

local udpDissectorTable = DissectorTable.get("udp.port")
udpDissectorTable:add("7777", unity)

io.stderr:write("Unity dissector successfully loaded\n")
