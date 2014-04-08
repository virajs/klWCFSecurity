using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security;


using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Configuration;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;
using System.Xml;

using klWCFCryptoHelper;

namespace WcfServiceLibrary
{
    public class CustomSecurityHeader : MessageHeader
    {
        private string _key;

        public string Key
        {
            get
            {
                return (this._key);
            }
        }

        public CustomSecurityHeader(string key)
        {
            this._key = key;
        }

        public override string Name
        {
            get { return (CustomHeaderNames.CustomHeaderName); }
        }
 
        public override string Namespace
        {
            get { return (CustomHeaderNames.CustomHeaderNamespace); }
        }

        protected override void OnWriteHeaderContents(System.Xml.XmlDictionaryWriter writer, MessageVersion messageVersion)
        {

            writer.WriteElementString(CustomHeaderNames.KeyName, this.Key);
        }

        public static CustomSecurityHeader ReadHeader(XmlDictionaryReader reader)
        {
            if (reader.ReadToDescendant(CustomHeaderNames.KeyName, CustomHeaderNames.CustomHeaderNamespace))
            {
                String key = reader.ReadElementString();
                return (new CustomSecurityHeader(key));
            }
            else
            {
                return null;
            }
        }
    }

    public static class CustomHeaderNames
    {
        public const String CustomHeaderName = "CustomSecurityHeader";

        public const String KeyName = "Key";

        public const String CustomHeaderNamespace = "http://schemas.kl.com/CustomSecurityHeader";

    }

    
    [MessageInspectionBehavior]
    public class Service1 : IService1
    {
        public string GetData(int value)
        {
            return string.Format("You entered: {0}", value * 2);
        }

        public CompositeType GetDataUsingDataContract(CompositeType composite)
        {
            if (composite.BoolValue)
            {
                composite.StringValue += "Suffix";
            }
            return composite;
        }
    }

    [AttributeUsage(AttributeTargets.Class)]
    public class MessageInspectionBehavior : Attribute, IServiceBehavior
    {
        #region IServiceBehavior Members

        public void AddBindingParameters(ServiceDescription serviceDescription, System.ServiceModel.ServiceHostBase serviceHostBase, System.Collections.ObjectModel.Collection<ServiceEndpoint> endpoints, System.ServiceModel.Channels.BindingParameterCollection bindingParameters)
        {
        }

        public void ApplyDispatchBehavior(ServiceDescription serviceDescription, System.ServiceModel.ServiceHostBase serviceHostBase)
        {
            for (Int32 i = 0; i < serviceHostBase.ChannelDispatchers.Count; i++)
            {
                ChannelDispatcher channelDispatcher = serviceHostBase.ChannelDispatchers[i] as ChannelDispatcher;
                if (channelDispatcher != null)
                {
                    foreach (EndpointDispatcher endpointDispatcher in channelDispatcher.Endpoints)
                    {
                        SecurityMessageInspector inspector = new SecurityMessageInspector();
                        endpointDispatcher.DispatchRuntime.MessageInspectors.Add(inspector);
                    }
                }
            }
        }

        public void Validate(ServiceDescription serviceDescription, System.ServiceModel.ServiceHostBase serviceHostBase)
        {
        }

        #endregion
    }

    public class ConsoleOutputBehaviorExtensionElement : BehaviorExtensionElement
    {
        public ConsoleOutputBehaviorExtensionElement()
        {
        }

        public override Type BehaviorType
        {
            get
            {
                return typeof(SecurityMessageInspector);
            }
        }

        protected override object CreateBehavior()
        {
            return new SecurityMessageInspector();
        }
    }

    public class SecurityMessageInspector : IDispatchMessageInspector, IClientMessageInspector
    {
        //Server Side
        public object AfterReceiveRequest(ref Message request, IClientChannel channel, InstanceContext instanceContext)
        {
            MessageBuffer buffer = request.CreateBufferedCopy(Int32.MaxValue);
            request = buffer.CreateMessage();
            Message originalMessage = buffer.CreateMessage();
            foreach (MessageHeader h in originalMessage.Headers)
            {
                Console.WriteLine("\n{0}\n", h);
            }
            MessageHeader myHeader = MessageHeader.CreateHeader("MyHeader", "ns", "ABC");
            request.Headers.Add(myHeader);



            return null;
        }

        //Server Side 
        public void BeforeSendReply(ref Message reply, object correlationState)
        {
            MessageBuffer buffer = reply.CreateBufferedCopy(0x7fffffff);
            reply = buffer.CreateMessage();
            Message originalMessage = buffer.CreateMessage();
            foreach (MessageHeader h in originalMessage.Headers)
            {
                Console.WriteLine("\n{0}\n", h);
            }
            MessageHeader myHeader = MessageHeader.CreateHeader("MyHeader", "ns", "ABC");
            reply.Headers.Add(myHeader);
        }

        //Client Side
        public void AfterReceiveReply(ref Message reply, object correlationState)
        {
            MessageBuffer buffer = reply.CreateBufferedCopy(0x7fffffff);
            reply = buffer.CreateMessage();
            Message originalMessage = buffer.CreateMessage();
            foreach (MessageHeader h in originalMessage.Headers)
            {
                Console.WriteLine("\n{0}\n", h);
            }
            MessageHeader myHeader = MessageHeader.CreateHeader("MyHeader", "ns", "ABC");
            reply.Headers.Add(myHeader);
        }

        //Client Side
        public object BeforeSendRequest(ref Message request, IClientChannel channel)
        {
            MessageBuffer buffer = request.CreateBufferedCopy(Int32.MaxValue);
            request = buffer.CreateMessage();
            Message originalMessage = buffer.CreateMessage();
            foreach (MessageHeader h in originalMessage.Headers)
            {
                Console.WriteLine("\n{0}\n", h);
            }
            MessageHeader myHeader = MessageHeader.CreateHeader("MyHeader", "ns", "ABC");
            request.Headers.Add(myHeader);
            return null;
        }


    }

    public class MessageBehaviorExtensionElement : BehaviorExtensionElement
    {
        public MessageBehaviorExtensionElement()
        {
        }

        public override Type BehaviorType
        {
            get
            {
                return typeof(ConsoleOutputBehavior);
            }
        }

        protected override object CreateBehavior()
        {
            return new ConsoleOutputBehavior();
        }
    }
    
    public class ConsoleOutputMessageInspector : IDispatchMessageInspector, IClientMessageInspector
    {
        //Server Side
        public object AfterReceiveRequest(ref System.ServiceModel.Channels.Message request, System.ServiceModel.IClientChannel channel, System.ServiceModel.InstanceContext instanceContext)
        {
            return null;
        }

        //Server Side
        public void BeforeSendReply(ref System.ServiceModel.Channels.Message reply, object correlationState)
        {
           X509Certificate2 myCert = CryptoHelper.FindCertificate(StoreLocation.LocalMachine, StoreName.My, X509FindType.FindBySubjectDistinguishedName, "CN=klServer");
            byte[] myHash = myCert.GetCertHash();

            byte[] mySignedHash = CryptoHelper.Sign(myHash, myCert);
            byte[] mySignedDetachedHash = CryptoHelper.SignDetached(myHash, myCert);

            byte[] myEncryptedHash = CryptoHelper.Encrypt(mySignedHash, myCert);
            byte[] myEncryptedDetachedHash = CryptoHelper.Encrypt(mySignedDetachedHash, myCert);

            byte[] myDecodedHash = CryptoHelper.VerifyAndRemoveSignature(mySignedHash);

            bool myOK = CryptoHelper.VerifyDetached(mySignedHash, mySignedDetachedHash);
           
            char[] keyChars = new char[mySignedHash.Length];

            for (int i = 0; i < mySignedHash.Length; i++)
                keyChars[i] = (char)mySignedHash[i];

            reply.Headers.Add((new CustomSecurityHeader(new string(keyChars))));
            
            MessageBuffer buffer = reply.CreateBufferedCopy(Int32.MaxValue);
            reply = buffer.CreateMessage();
            Console.WriteLine("Service Sending:\n{0}", buffer.CreateMessage().ToString());
        }

        //Client Side
        public void AfterReceiveReply(ref Message reply, object correlationState)
        {
            MessageBuffer buffer = reply.CreateBufferedCopy(Int32.MaxValue);
            reply = buffer.CreateMessage();
            Console.WriteLine("Client Received:\n{0}", buffer.CreateMessage().ToString());
            
            X509Certificate2 myCert = CryptoHelper.FindCertificate(StoreLocation.LocalMachine, StoreName.My, X509FindType.FindBySubjectDistinguishedName, "CN=klServer");
            byte[] myHash = myCert.GetCertHash();

            Int32 headerPosition = reply.Headers.FindHeader(CustomHeaderNames.CustomHeaderName, CustomHeaderNames.CustomHeaderNamespace);

            XmlDictionaryReader reader = reply.Headers.GetReaderAtHeader(headerPosition);

            CustomSecurityHeader header = CustomSecurityHeader.ReadHeader(reader); 

            string mySignedHashString = header.Key;

            char[] mysignedHashCharArray = mySignedHashString.ToArray();
           
            byte[] mySignedHash = new byte[mySignedHashString.Length];
            for (int i = 0; i < mySignedHashString.Length; i++)
                mySignedHash[i] =(byte) mysignedHashCharArray[i];
  
            byte[] myDecodedHash = CryptoHelper.VerifyAndRemoveSignature(mySignedHash);

            for(int i=0;i<myHash.Length;i++)
            {
                if (myDecodedHash[i] != myHash[i])
                {
                    throw new Exception("Access Denied");
                }
            }
        }

        public object BeforeSendRequest(ref Message request, IClientChannel channel)
        {

            return null;
        }

    }

    public class ConsoleOutputBehavior : IEndpointBehavior
    {
        #region IEndpointBehavior Members

        public void AddBindingParameters(ServiceEndpoint endpoint, System.ServiceModel.Channels.BindingParameterCollection bindingParameters)
        {
        }

        public void ApplyClientBehavior(ServiceEndpoint endpoint, System.ServiceModel.Dispatcher.ClientRuntime clientRuntime)
        {
            ConsoleOutputMessageInspector inspector = new ConsoleOutputMessageInspector();
            clientRuntime.MessageInspectors.Add(inspector);
        }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, System.ServiceModel.Dispatcher.EndpointDispatcher endpointDispatcher)
        {
            ConsoleOutputMessageInspector inspector = new ConsoleOutputMessageInspector();
            endpointDispatcher.DispatchRuntime.MessageInspectors.Add(inspector);
        }

        public void Validate(ServiceEndpoint endpoint)
        {
        }

        #endregion
    }
}
