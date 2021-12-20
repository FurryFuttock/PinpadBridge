using System;
using System.Collections.Generic;
using System.ServiceProcess;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;
using System.IO.Ports;
using System.Threading;
using Newtonsoft.Json;

namespace PinpadBridge
{
    public partial class PinpadBridgeService : ServiceBase
    {
        #region REST API
        public class Response
        {
            public int ResponseCode;
            public string ResponseDescription;
        }

        public class Response_Status : Response
        {
        }

        public class Request_Mensaje
        {
            public int DisplayDuration;
            public string[] Message;
        }

        public class Response_Mensaje : Response
        {
        }

        public class Request_Seleccion
        {
            public int DisplayDuration;
            public int ValueMaximum;
            public string[] Message;
        }

        public class Response_Seleccion : Response
        {
            public string Value;
        }

        public class Request_LecturaTarjeta
        {
            public int Store;
            public int Amount;
            public String Currency;
            public String CardType;
        }

        public class Response_LecturaTarjeta : Response
        {
            public String CaptureType;
            public String Track1;
            public String Track2;
            public String CardNumber;
            public String CardHolderName;
            public String CardTypeName;
            public String CardTypeAbbreviation;
        }

        public class Request_CargaLlaves
        {
            public int KeyNumber;
            public String AuthenticationKey;
            public String DataEncryptionKey;
            public String DataEncryptionKeyII;
        }

        public class Response_CargaLlaves : Response
        {
        }

        public class Request_LecturaPin
        {
            public int PinLength;
            public string WorkingKey;
            public string[] Message;
        }

        public class Response_LecturaPin : Response
        {
            public String PinBlock;
        }

        [ServiceContract]
        public interface IPinpadBridge
        {
            [OperationContract, WebInvoke(UriTemplate = "/ConsultaEstado", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response_Status ConsultaEstado();
            [OperationContract, WebInvoke(UriTemplate = "/Mensaje", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response_Mensaje Mensaje(Request_Mensaje request);
            [OperationContract, WebInvoke(UriTemplate = "/Seleccion", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response_Seleccion Seleccion(Request_Seleccion request);
            [OperationContract, WebInvoke(UriTemplate = "/LecturaTarjeta", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response_LecturaTarjeta LecturaTarjeta(Request_LecturaTarjeta request);
            [OperationContract, WebInvoke(UriTemplate = "/CargaLlaves", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response_CargaLlaves CargaLlaves(Request_CargaLlaves request);
            [OperationContract, WebInvoke(UriTemplate = "/LecturaPin", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response_LecturaPin LecturaPin(Request_LecturaPin request);
        }

        public class PinpadBridge : IPinpadBridge
        {
            #region Configuration
            Properties.PinpadBridge settings = new Properties.PinpadBridge();
            #endregion

            #region Serial
            static ManualResetEvent have_response = new ManualResetEvent(false);
            static ManualResetEvent have_ack = new ManualResetEvent(false);
            static String receive_string = "";

            const byte STX = 0x02;
            const byte ETX = 0x03;
            const byte ACK = 0x06;
            const byte NAK = 0x15;

            static private SerialPort serial_port = null;
            byte[] receive_data = new byte[256];
            byte[] receive_buffer = new byte[256];
            int receive_data_length = 0;
            byte received_lrc = 0;

            enum ReceiveStatus { idle, data, lrc };
            ReceiveStatus receive_status = ReceiveStatus.idle;

            private bool SerialPort_DoIt(String[] input_fields, out String[] output_fields, int timeout_s)
            {
                bool rc = false;
                have_ack.Reset();
                have_response.Reset();
                if (SerialPort_Send(input_fields))
                {
                    WriteLog("Wait for ACK...");
                    if (have_ack.WaitOne(settings.Pinpad_AckTimeoutS * 1000))
                    {
                        WriteLog("Have ACK");
                        WriteLog("Wait for response...");
                        if (have_response.WaitOne(timeout_s * 1000))
                        {
                            WriteLog($"Have response [{receive_string}]");
                            rc = true;
                        }
                        else
                        {
                            WriteLog("Timeout waiting for response");
                        }
                    }
                    else
                    {
                        WriteLog("Timeout waiting for ACK");
                    }
                }

                output_fields = rc ? receive_string.Split('|') : null;
                return rc;
            }

            private bool SerialPort_Send(String[] fields)
            {
                bool rc = false;

                try
                {
                    // Create the message
                    // <STX>Field0|Field1|...|Fieldn|<ETX><LRC>
                    List<byte> data = new List<byte>();
                    data.Add(STX);
                    foreach (String field in fields)
                    {
                        data.AddRange(ASCIIEncoding.ASCII.GetBytes(field));
                        data.Add((byte)'|');
                    }
                    data.Add(ETX);

                    // Calculate the LRC
                    // The LRC is calculated on everything AFTER STX
                    // We initialised LRC with STX so when we process STX it will go back to 0
                    byte lrc = STX;
                    foreach (byte b in data)
                    {
                        lrc ^= b;
                    }
                    data.Add(lrc);

                    // Send the packet
                    WriteLog("Send: {0}", ASCIIEncoding.ASCII.GetString(data.ToArray(), 0, data.Count));
                    serial_port.Write(data.ToArray(), 0, data.Count);


                    rc = true;
                }
                catch (Exception ex)
                {
                    WriteLog("Error sending serial data: {0} {1}", ex.Message, ex.StackTrace);
                    rc = false;
                }

                return rc;
            }

            private void SerialPort_DataReceived(object sender, SerialDataReceivedEventArgs e)
            {
                int size = serial_port.Read(receive_buffer, 0, receive_buffer.Length);
                WriteLog("Receive {0} bytes", size);
                int offset;
                for (offset = 0; offset < size; offset++)
                {
                    byte chr = receive_buffer[offset];

                    // If we have an STX then restart the state machine
                    if ((chr == STX) && (receive_status != ReceiveStatus.lrc))
                    {
                        receive_status = ReceiveStatus.idle;
                        receive_data_length = 0;
                    }

                    WriteLog("Receive status={0} chr={1}/{2}", receive_status.ToString(), (int)chr, (char)chr);

                    if (receive_data_length >= receive_data.Length)
                        Array.Resize<Byte>(ref receive_data, receive_data.Length + 256);
                    receive_data[receive_data_length++] = chr;
                    received_lrc ^= chr;

                    switch (receive_status)
                    {
                    case ReceiveStatus.idle:
                        if (chr == STX)
                        {
                            receive_status = ReceiveStatus.data;
                            received_lrc = 0;
                        }
                        else if (chr == ACK)
                        {
                            WriteLog("Receive ACK");
                            have_ack.Set();
                        }
                        break;
                    case ReceiveStatus.data:
                        if (chr == ETX)
                        {
                            // Packet finished, process LRC
                            receive_status = ReceiveStatus.lrc;
                        }
                        break;
                    case ReceiveStatus.lrc:
                        receive_status = ReceiveStatus.idle;
                        if (received_lrc != 0)
                        {
                            // Tell the terminal that we had a problem
                            WriteLog($"Send: {(char)NAK}");
                            serial_port.Write(new byte[] { NAK }, 0, 1);

                            // Tell someone that we had a problem
                            WriteLog("Receive invalid LRC. Received {0:X}. Calculated {1:X}]", chr, received_lrc ^ chr);
                        }
                        else
                        {
                            // Tell the terminal that we received OK
                            WriteLog($"Send: {(char)ACK}");
                            serial_port.Write(new byte[] { ACK }, 0, 1);

                            // Convert the received data to a string.
                            receive_string = ASCIIEncoding.ASCII.GetString(receive_data, 1, (int)receive_data_length - 3);

                            // Tell the sender that we have a response
                            WriteLog("Receive response {0}", receive_string);
                            have_response.Set();
                        }
                        break;
                    }
                }
            }
            #endregion

            public PinpadBridge()
            {
                if (serial_port == null)
                {
                    serial_port = new SerialPort(settings.Port_Name, settings.Port_BaudRate, settings.Port_Parity, settings.Port_DataBits, settings.Port_StopBits);
                    serial_port.DataReceived += SerialPort_DataReceived;
                    serial_port.Open();
                }
            }

            ~PinpadBridge()
            {
            }

            public Response_Status ConsultaEstado()
            {
                // curl -X POST -H "Content-Type: application/json" -d "" http://localhost:8123/PinpadBridge/ConsultaEstado
                // {"ResponseCode":0,"ResponseDescription":"OK"}

                WriteLog("ConsultaEstado_Request: {0}", JsonConvert.SerializeObject("", new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                Response_Status response = new Response_Status();
                String[] response_fields;
                if (SerialPort_DoIt(new string[] { "1010", "00", "01" }, out response_fields, 35))
                {
                    if ((response_fields != null) && (response_fields.Length == 1) && (response_fields[0].Length == 1))
                    {
                        response.ResponseCode = (response_fields[0][0] == ACK) ? 0 : -1;
                        response.ResponseDescription = response.ResponseCode == 0 ? "OK" : "ERROR";
                    }
                    else
                    {
                        response.ResponseCode = -1;
                        response.ResponseDescription = "ERROR";
                    }
                }
                else
                {
                    response.ResponseCode = -1;
                    response.ResponseDescription = "ERROR";
                }
                WriteLog("ConsultaEstado_Response: {0}", JsonConvert.SerializeObject(response, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                return response;
            }

            public Response_Mensaje Mensaje(Request_Mensaje request)
            {
                // curl -X POST -H "Content-Type: application/json" -d '{"DisplayDuration":5,"Message": ["<----LINE 0---->","<----LINE 1---->","<----LINE 2---->","<----LINE 3---->"]}' http://localhost:8123/PinpadBridge/Mensaje
                // {"ResponseCode":0,"ResponseDescription":"OK"}

                WriteLog("Mensaje_Request: {0}", JsonConvert.SerializeObject(request, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                WriteLog("Mensaje_Request: {0}", JsonConvert.SerializeObject(request, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                Response_Mensaje response = new Response_Mensaje();
                String[] request_fields = new string[]
                {
                    "1020", request.DisplayDuration == 0 ? "00" : "01", request.DisplayDuration.ToString("00"),
                    Math.Min(request.Message.Length, 4).ToString("00"),
                    (request.Message.Length > 0 ? request.Message[0] : "").PadRight(16, ' ').Substring(0, 16),
                    (request.Message.Length > 1 ? request.Message[1] : "").PadRight(16, ' ').Substring(0, 16),
                    (request.Message.Length > 2 ? request.Message[2] : "").PadRight(16, ' ').Substring(0, 16),
                    (request.Message.Length > 3 ? request.Message[3] : "").PadRight(16, ' ').Substring(0, 16)
                };
                String[] response_fields;
                if (SerialPort_DoIt(request_fields, out response_fields, request.DisplayDuration == 0 ? 60 : request.DisplayDuration + 1))
                {
                    if ((response_fields != null) && (response_fields.Length == 3))
                    {
                        response.ResponseCode = int.Parse(response_fields[1]);
                        response.ResponseDescription = response.ResponseCode == 0 ? "OK" : "ERROR";
                    }
                    else
                    {
                        response.ResponseCode = -1;
                        response.ResponseDescription = "ERROR";
                    }
                }
                else
                {
                    response.ResponseCode = -1;
                    response.ResponseDescription = "ERROR";
                }
                WriteLog("Mensaje_Response: {0}", JsonConvert.SerializeObject(response, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                return response;
            }

            public Response_Seleccion Seleccion(Request_Seleccion request)
            {
                // curl -X POST -H "Content-Type: application/json" -d '{"DisplayDuration":5,"ValueMaximum":2,"Message": ["<----LINE 0---->","<----LINE 1---->","<----LINE 2---->","<----LINE 3---->"]}' http://localhost:8123/PinpadBridge/Mensaje
                // {"Value":"01","ResponseCode":0,"ResponseDescription":"OK"}

                WriteLog("Seleccion_Request: {0}", JsonConvert.SerializeObject(request, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                Response_Seleccion response = new Response_Seleccion();
                String[] request_fields = new string[]
                {
                    "1030", request.DisplayDuration == 0 ? "00" : "01", request.DisplayDuration.ToString("00"),
                    request.ValueMaximum.ToString("00"),
                    Math.Min(request.Message.Length, 4).ToString("00"),
                    (request.Message.Length > 0 ? request.Message[0] : "").PadRight(16, ' ').Substring(0, 16),
                    (request.Message.Length > 1 ? request.Message[1] : "").PadRight(16, ' ').Substring(0, 16),
                    (request.Message.Length > 2 ? request.Message[2] : "").PadRight(16, ' ').Substring(0, 16),
                    (request.Message.Length > 3 ? request.Message[3] : "").PadRight(16, ' ').Substring(0, 16)
                };
                String[] response_fields;
                if (SerialPort_DoIt(request_fields, out response_fields, request.DisplayDuration == 0 ? 60 : request.DisplayDuration + 1))
                {
                    if ((response_fields != null) && (response_fields.Length == 4))
                    {
                        response.ResponseCode = int.Parse(response_fields[1]);
                        response.ResponseDescription = response.ResponseCode == 0 ? "OK" : "ERROR";
                        response.Value = response.ResponseCode == 0 ? response_fields[2] : "";
                    }
                    else
                    {
                        response.ResponseCode = -1;
                        response.ResponseDescription = "ERROR";
                    }
                }
                else
                {
                    response.ResponseCode = -1;
                    response.ResponseDescription = "ERROR";
                }
                WriteLog("Seleccion_Response: {0}", JsonConvert.SerializeObject(response, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                return response;
            }

            public Response_LecturaTarjeta LecturaTarjeta(Request_LecturaTarjeta request)
            {
                // curl -X POST -H "Content-Type: application/json" -d '{"Store":0,"Amount":123400,"Currency":"CL","CardType":"CR"}' http://localhost:8123/PinpadBridge/LecturaTarjeta
                // {"CaptureType":"00","Track1":"...","Track2":"...","CardNumber":"...","CardHolderName":"...","CardTypeName":"...","CardTypeAbbreviation":"...","ResponseCode":0,"ResponseDescription":"OK"}

                WriteLog("LecturaTarjeta_Request: {0}", JsonConvert.SerializeObject(request, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                Response_LecturaTarjeta response = new Response_LecturaTarjeta();
                String[] request_fields = new string[]
                {
                    "1040",
                    request.Store.ToString("00"),
                    request.Amount.ToString("000000000000000000"),
                    request.Currency,
                    request.CardType
                };
                String[] response_fields;
                if (SerialPort_DoIt(request_fields, out response_fields, 35))
                {
                    if ((response_fields != null) && (response_fields.Length == 10))
                    {
                        response.ResponseCode = int.Parse(response_fields[1]);
                        response.ResponseDescription = response.ResponseCode == 0 ? "OK" : "ERROR";
                        response.CaptureType = response_fields[2];
                        response.Track1 = response_fields[3];
                        response.Track2 = response_fields[4];
                        response.CardNumber = response_fields[5];
                        response.CardHolderName = response_fields[6];
                        response.CardTypeName = response_fields[7];
                        response.CardTypeAbbreviation = response_fields[8];
                    }
                    else
                    {
                        response.ResponseCode = -1;
                        response.ResponseDescription = "ERROR";
                    }
                }
                else
                {
                    response.ResponseCode = -1;
                    response.ResponseDescription = "ERROR";
                }
                WriteLog("LecturaTarjeta_Response: {0}", JsonConvert.SerializeObject(response, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                return response;
            }

            public Response_CargaLlaves CargaLlaves(Request_CargaLlaves request)
            {
                // curl -X POST -H "Content-Type: application/json" -d '{"KeyNumber":0,"AuthenticationKey":"...","DataEncryptionKey":"...","DataEncryptionKeyII":"..."}' http://localhost:8123/PinpadBridge/CargaLlaves
                // {"ResponseCode":0,"ResponseDescription":"OK"}

                WriteLog("CargaLlaves_Request: {0}", JsonConvert.SerializeObject(request, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                Response_CargaLlaves response = new Response_CargaLlaves();
                String[] request_fields = new string[]
                {
                    "1050",
                    request.KeyNumber.ToString("0"),
                    request.AuthenticationKey.PadRight(32, ' ').Substring(0, 32),
                    request.DataEncryptionKey.PadRight(32, ' ').Substring(0, 32),
                    request.DataEncryptionKeyII.PadRight(32, ' ').Substring(0, 32),
                };
                String[] response_fields;
                if (SerialPort_DoIt(request_fields, out response_fields, 120))
                {
                    if ((response_fields != null) && (response_fields.Length == 3))
                    {
                        response.ResponseCode = int.Parse(response_fields[1]);
                        response.ResponseDescription = response.ResponseCode == 0 ? "OK" : "ERROR";
                    }
                    else
                    {
                        response.ResponseCode = -1;
                        response.ResponseDescription = "ERROR";
                    }
                }
                else
                {
                    response.ResponseCode = -1;
                    response.ResponseDescription = "ERROR";
                }
                WriteLog("CargaLlaves_Response: {0}", JsonConvert.SerializeObject(response, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                return response;
            }

            public Response_LecturaPin LecturaPin(Request_LecturaPin request)
            {
                // curl -X POST -H "Content-Type: application/json" -d '{"PinLength":4,"WorkingKey":null,"Message":["<----LINE 1---->","<----LINE 1---->"]}' http://localhost:8123/PinpadBridge/LecturaPin
                // {"PinBlock":"...","ResponseCode":0,"ResponseDescription":"OK"}

                WriteLog("LecturaPin_Request: {0}", JsonConvert.SerializeObject(request, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                Response_LecturaPin response = new Response_LecturaPin();
                String[] request_fields = new string[]
                {
                    "1060",
                    request.PinLength.ToString("0"),
                    String.IsNullOrEmpty(request.WorkingKey) ? "0" : "1",
                    (String.IsNullOrEmpty(request.WorkingKey) ? "" : request.WorkingKey).PadRight(32, ' ').Substring(0, 32),
                    (request.Message.Length > 0 ? request.Message[0] : "").PadRight(16, ' ').Substring(0, 16),
                    (request.Message.Length > 1 ? request.Message[1] : "").PadRight(16, ' ').Substring(0, 16),
                };
                String[] response_fields;
                if (SerialPort_DoIt(request_fields, out response_fields, 120))
                {
                    if ((response_fields != null) && (response_fields.Length == 3))
                    {
                        response.ResponseCode = int.Parse(response_fields[1]);
                        response.ResponseDescription = response.ResponseCode == 0 ? "OK" : "ERROR";
                        response.PinBlock = response_fields[2];
                    }
                    else
                    {
                        response.ResponseCode = -1;
                        response.ResponseDescription = "ERROR";
                    }
                }
                else
                {
                    response.ResponseCode = -1;
                    response.ResponseDescription = "ERROR";
                }
                WriteLog("LecturaPin_Response: {0}", JsonConvert.SerializeObject(response, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                return response;
            }
        }

        WebServiceHost host = null;
        #endregion

        public PinpadBridgeService()
        {
            InitializeComponent();
        }

        static public void WriteLog(String format, params object[] vs)
        {
            // create this data
            Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {String.Format(format, vs)}");
        }

        protected override void OnStart(string[] args)
        {
            DoStart();
        }

        protected override void OnStop()
        {
            DoStop();
        }

        public void DoStart()
        {
            Properties.PinpadBridge settings = new Properties.PinpadBridge();
            host = new WebServiceHost(typeof(PinpadBridge), new Uri(settings.Http_Url));
            host.Open();
        }

        public void DoStop()
        {
            host.Close();
        }
    }
}
