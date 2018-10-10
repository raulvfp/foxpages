#INCLUDE foxpages.h

******************************************************************************************
* WebSocket class
*****************
DEFINE CLASS WebSocket AS CUSTOM
	*--- Internal properties
	Directory    = ""
	Document_URI = ""

	*--- Received data buffer
	Buffer = ""

	*--- WebSocket ReadyState
	* 0 - Connecting
	* 1 - Open
	* 2 - Closing
	* 3 - Closed
	ReadyState = 1

	*--- Compression enabled
	Compression = .F.

	PROCEDURE Init()
		*--- Debug log
		This.Parent.Log.Add(2,"Websocket.Init")

		*--- Update Thread Type
		This.Parent.Type = "WebSocket"
	ENDPROC

	PROCEDURE Destroy()
	ENDPROC

	PROCEDURE Error(nError,cMethod,nLine)
		This.Parent.Log.Add(0,"Websocket.Error","Method: "+proper(m.cMethod)+CRLF+"Message: "+message())
	ENDPROC

	PROCEDURE Close(Status AS Character)
		*--- Debug log
		This.Parent.Log.Add(2,"Websocket.Close")

		*--- Set WebSocket ReadyState to Closing
		This.ReadyState = 2

		*--- Send close frame
		This.Send(m.Status,8)
	ENDPROC

	PROCEDURE Ping(Data AS Character)
		*--- Debug log
		This.Parent.Log.Add(2,"Websocket.Ping")

		*--- Send ping frame
		This.Send(m.Data,9)
	ENDPROC

	PROCEDURE Pong(Data AS Character)
		*--- Debug log
		This.Parent.Log.Add(2,"Websocket.Pong")
		
		wait window m.Data nowait
	ENDPROC

	PROCEDURE Process()
	LOCAL lnByte,llFin,llRsv1,llRsv2,llRsv3,lnOpcode,llMask,lnPayloadLength,lnPayloadStart,lcMask

		*--- Frame data
		m.lnByte = asc(substr(This.Parent.Buffer,1,1))

		*--- Final fragment
		m.llFin = bittest(m.lnByte,7)

		*--- Should be zero or MUST fail the connection
		m.llRsv1 = bittest(m.lnByte,6)
		m.llRsv2 = bittest(m.lnByte,5)
		m.llRsv3 = bittest(m.lnByte,4)

		if m.llRsv1 AND !This.Compression
			*--- Compressed data without compression been negociated in the connection handshake
			This.Close("1002")
			
			return .F.
		endif
		
		*--- Defines the interpretation of the "Payload data"
		m.lnOpcode = bitclear(bitclear(bitclear(bitclear(m.lnByte,7),6),5),4)

		*--- Frame data
		m.lnByte = asc(substr(This.Parent.Buffer,2,1))

		*--- Defines whether the "Payload data" is masked
		m.llMask = bittest(m.lnByte,7)

		*--- The length of the "Payload data"
		m.lnPayloadLength = bitclear(m.lnByte,7)

		do case
		case m.lnPayloadLength = 127
			*--- If 127, the following 8 bytes interpreted as a 64-bit unsigned integer
			m.lnPayloadLength = Bin2UInt(substr(This.Parent.Buffer,3,8))
			m.lnPayloadStart = 10
		case m.lnPayloadLength = 126
			*--- If 126, the following 2 bytes interpreted as a 16-bit unsigned integer are the payload length
			m.lnPayloadLength = Bin2UInt(substr(This.Parent.Buffer,3,2))
			m.lnPayloadStart = 4
		otherwise
			*--- The following byte interpreted as a 8-bit unsigned integer is the payload length
			m.lnPayloadStart = 2
		endcase

		if m.llMask
			*--- Defines whether the "Payload data" is masked.
			m.lcMask = substr(This.Parent.Buffer,m.lnPayloadStart+1,4)
			m.lnPayloadStart = m.lnPayloadStart + 4
		endif

		*--- Incomplete frame, wait next read event.
		if len(This.Parent.Buffer) < m.lnPayloadStart+m.lnPayloadLength
			return .T.
		endif

		*--- Unmask "Payload data"
		This.Buffer = This.Buffer + XORCrypt(substr(This.Parent.Buffer,m.lnPayloadStart+1,m.lnPayloadLength),m.lcMask)

		*--- Remove frame from thread buffer
		This.Parent.Buffer = substr(This.Parent.Buffer,m.lnPayloadStart+m.lnPayloadLength+1)

		*--- Check if its the last frame
		if !llFin
			return .T.
		endif

*!*			if m.llRsv1
*!*				*--- Can't decompress data
*!*			endif

		*--- OpCodes
		do case
		case m.lnOpCode = 1 OR m.lnOpCode = 2
			if m.lnOpCode = 1
				*--- Convert text data from UTF-8
				This.Buffer = strconv(This.Buffer,11)
			endif

			*--- TODO: What do I do with the data? :)
			wait window This.Buffer nowait
		case m.lnOpCode = 8
			do case
			case This.ReadyState = 1 && Open
				*--- Set WebSocket ReadyState to Closing
				This.ReadyState = 2

				*--- Send close frame
				This.Send(This.Buffer,8)
			case This.ReadyState = 2 && Closing
				*--- Set WebSocket ReadyState to Closed
				This.ReadyState = 3
			endcase

			*--- Disconnect
			This.Parent.Disconnect()

			*--- Update Thread Type
			This.Parent.Type = "HTTP"

			*--- Debug log
			This.Parent.Log.Add(2,"Websocket.Destroy")

			*--- Remove WebSocket
			This.Parent.RemoveObject("WebSocket")
		case m.lnOpCode = 9
			*--- Ping frame
			This.Send(This.Buffer,10)
		case m.lnOpCode = 10
			*--- Pong frame
			This.Pong(This.Buffer)
		endcase

		*--- Clear buffer
		This.Buffer = ""
	ENDPROC

	PROCEDURE Send(Data AS String, Type AS Number)
	LOCAL lcFrame
		*--- Check m.Data
		if empty(m.Data)
			m.Data = ""
		endif

*!*			*--- Data compression
*!*			if This.Compression
*!*				*--- Set to binary data
*!*				m.Type = 2
*!*				
*!*				*--- Can´t compress data
*!*				m.Data = ???
*!*			endif
		
		*--- Fin frame and Opcode (1 = Text, 2 = Binary)
		m.lcFrame = UInt2Bin(bitset(m.Type,7),1)

		*--- Binary type
		do case
		case m.Type = 1
			*--- Convert text data to UTF-8
			m.Data = strconv(m.Data,9)
		case m.Type = 2
			*--- Convert binary data to Byte Array
			m.Data = createbinary(m.Data)
		endcase

		*--- Frame lenght
		do case
		case len(m.Data) > 32768
			*--- If 127, the following 8 bytes interpreted as a 64-bit unsigned integer
			m.lcFrame = m.lcFrame + UInt2Bin(127,1) + UInt2Bin(len(m.Data),8)
		case len(m.Data) > 125
			*--- If 126, the following 2 bytes interpreted as a 16-bit unsigned integer are the payload length.
			m.lcFrame = m.lcFrame + UInt2Bin(126,1) + UInt2Bin(len(m.Data),2)
		otherwise
			*--- The following byte interpreted as a 8-bit unsigned integer is the payload length
			m.lcFrame = m.lcFrame + UInt2Bin(len(m.Data),1)
		endcase

		*--- Send frame
		This.Parent.Socket.Write(m.lcFrame + m.Data)
	ENDPROC
ENDDEFINE

*--- BitXOR Cryptographic Function
FUNCTION XORCrypt(Source AS String, Key AS String)
LOCAL lnCtrl, lcResult

	m.lcResult = ""
	for m.lnPos = 1 to len(m.Source)
		m.lcResult = m.lcResult + chr(bitxor(asc(substr(m.Source,m.lnPos,1)),asc(substr(m.Key,mod(m.lnPos-1,len(m.Key))+1,1))))
	next

	return m.lcResult
ENDFUNC