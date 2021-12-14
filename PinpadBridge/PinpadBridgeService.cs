using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.ServiceProcess;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;
using System.Threading.Tasks;
using System.IO.Ports;
using System.Threading;
using System.Reflection;

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

        public class Request_LecturaPin
        {
            public int PinLength;
            public bool HaveWorkingKey;
            public string WorkingKey;
            public string Message1;
            public string Message2;
        }

        public class Response_LecturaPin : Response
        {
        }

        [ServiceContract]
        public interface IPinpadBridge
        {
            [OperationContract, WebInvoke(UriTemplate = "/ConsultaEstado", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response_Status ConsultaEstado();
            [OperationContract, WebInvoke(UriTemplate = "/Mensaje", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response Mensaje();
            [OperationContract, WebInvoke(UriTemplate = "/Seleccion", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response Seleccion();
            [OperationContract, WebInvoke(UriTemplate = "/LecturaTarjeta", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response LecturaTarjeta();
            [OperationContract, WebInvoke(UriTemplate = "/CargaLlaves", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response CargaLlaves();
            [OperationContract, WebInvoke(UriTemplate = "/LecturaPin", Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
            Response_LecturaPin LecturaPin(Request_LecturaPin request);
        }

        public class PinpadBridge : IPinpadBridge
        {
            #region Configuration
            String Port_Name = "COM3";
            int Port_BaudRate = 115200;
            Parity Port_Parity = Parity.None;
            int Port_DataBits = 8;
            StopBits Port_StopBits = StopBits.One;
            int Terminal_AckTimeoutMs = 10000;
            #endregion

            #region Serial
            AutoResetEvent have_response = new AutoResetEvent(false);
            AutoResetEvent have_ack = new AutoResetEvent(false);
            String receive_string = "";

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

            private bool SerialPort_DoIt(String[] input_fields, out String[] output_fields, int timeout_ms)
            {
                bool rc = false;
                have_response.Reset();
                if (SerialPort_Send(input_fields))
                {
                    if (have_ack.WaitOne(Terminal_AckTimeoutMs) && have_response.WaitOne(timeout_ms))
                    {
                        rc = true;
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

                    WriteLog("Status={0} Chr={1}/{2}", receive_status.ToString(), (int)chr, (char)chr);

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
                            serial_port.Write(new byte[] { NAK }, 0, 1);

                            // Tell someone that we had a problem
                            WriteLog("Recv: Invalid LRC. Received {0:X}. Calculated {1:X}]", chr, received_lrc ^ chr);
                        }
                        else
                        {
                            // Tell the terminal that we received OK
                            serial_port.Write(new byte[] { ACK }, 0, 1);

                            // Convert the received data to a string.
                            receive_string = ASCIIEncoding.ASCII.GetString(receive_data, 0, (int)receive_data_length);

                            // Tell the sender that we have a response
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
                    serial_port = new SerialPort(Port_Name, Port_BaudRate, Port_Parity, Port_DataBits, Port_StopBits);
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
                // { "ResponseCode":-1,"ResponseDescription":"Not Implemented"}

                Response_Status response = new Response_Status();
                String[] response_fields;
                if (!SerialPort_DoIt(new string[] { "1010", "00", "01" }, out response_fields, 35000))
                {
                    if ((response_fields != null) && (response_fields.Length == 2))
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
                return response;
            }

            public Response Mensaje()
            {
                // curl -X POST -H "Content-Type: application/json" -d "" http://localhost:8123/PinpadBridge/Mensaje
                // { "ResponseCode":-1,"ResponseDescription":"Not Implemented"}

                Response response = new Response();
                response.ResponseCode = -1;
                response.ResponseDescription = "Not Implemented";
                return response;
            }

            public Response Seleccion()
            {
                // curl -X POST -H "Content-Type: application/json" -d "" http://localhost:8123/PinpadBridge/Seleccion
                // { "ResponseCode":-1,"ResponseDescription":"Not Implemented"}

                Response response = new Response();
                response.ResponseCode = -1;
                response.ResponseDescription = "Not Implemented";
                return response;
            }

            public Response LecturaTarjeta()
            {
                // curl -X POST -H "Content-Type: application/json" -d "" http://localhost:8123/PinpadBridge/LecturaTarjeta
                // { "ResponseCode":-1,"ResponseDescription":"Not Implemented"}

                Response response = new Response();
                response.ResponseCode = -1;
                response.ResponseDescription = "Not Implemented";
                return response;
            }

            public Response CargaLlaves()
            {
                // curl -X POST -H "Content-Type: application/json" -d "" http://localhost:8123/PinpadBridge/CargaLlaves
                // { "ResponseCode":-1,"ResponseDescription":"Not Implemented"}

                Response response = new Response();
                response.ResponseCode = -1;
                response.ResponseDescription = "Not Implemented";
                return response;
            }

            public Response_LecturaPin LecturaPin(Request_LecturaPin request)
            {
                // curl -X POST -H "Content-Type: application/json" -d '{"PinLength":4, "HaveWorkingKey": true, "WorkingKey": "abc123", "Message1": "aaaa", "Message2": "bbbb"}' http://localhost:8123/PinpadBridge/LecturaPin
                // { "ResponseCode":0,"ResponseDescription":"OK"}

                SerialPort_Send(new string[] { "1060", request.PinLength.ToString(), request.HaveWorkingKey ? "1" : "0", request.WorkingKey, request.Message1, request.Message2 });
                
                Response_LecturaPin response = new Response_LecturaPin();
                response.ResponseCode = 0;
                response.ResponseDescription = "OK";
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
            Console.WriteLine(new string[] { $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}", String.Format(format, vs) });
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
            String base_address = "http://localhost:8123/PinpadBridge";
            host = new WebServiceHost(typeof(PinpadBridge), new Uri(base_address));
            host.Open();
        }

        public void DoStop()
        {
            host.Close();
        }
    }
}
