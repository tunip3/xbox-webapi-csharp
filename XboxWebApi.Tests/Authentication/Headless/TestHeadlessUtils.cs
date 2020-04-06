using System;
using System.IO;
using System.Collections.Generic;
using NUnit.Framework;
using XboxWebApi.Common;
using XboxWebApi.Authentication;
using XboxWebApi.Authentication.Model;
using XboxWebApi.Authentication.Headless;

namespace XboxWebApi.UnitTests.Authentication.Headless
{
    [TestFixture]
    public class TestHeadlessUtils : TestDataProvider
    {
        public TestHeadlessUtils()
            : base("Authentication")
        {
        }

        [Test]
        public void TestExtractJsObject()
        {
            string responseBody = TestData["wl_auth_response.html"];
            var dict = Utils.ExtractJsObject(responseBody, "var ServerData");

            Assert.NotNull(dict);
            Assert.AreEqual("<input name=\"PPFT\" value=\"normally_base64_encoded_string_here+\"/>", dict["sFTTag"]);
        }

        [Test]
        public void TestParseXmlNode()
        {
            string node = "<input name=\"PPFT\" value=\"U29tZVN0cmluZwo=\"/>";

            var result = Utils.ParseXmlNode(node);

            Assert.NotNull(result);

            var ppft = result.GetElementsByTagName("input")[0].Attributes["value"].Value;
            Assert.AreEqual("U29tZVN0cmluZwo=", ppft);
        }
    }
}