//------------------------------------------------------------------------------
// <copyright file="SecurityUtil.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

/*
 * SecurityUtil class
 *
 * Copyright (c) 1999 Microsoft Corporation
 */

using System;
using System.Globalization;
using System.Web.Hosting;
using System.Collections;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Configuration;
using System.Xml;

namespace Mild.MembershipProvider.Helpers
{
    internal static class SecUtility {

        internal const int Infinite = Int32.MaxValue;
        internal static string GetDefaultAppName()
        {
            try {
                string appName = HostingEnvironment.ApplicationVirtualPath;
                if (String.IsNullOrEmpty(appName)) {

                    appName = System.Diagnostics.Process.GetCurrentProcess().
                                     MainModule.ModuleName;

                    int indexOfDot = appName.IndexOf('.');
                    if (indexOfDot != -1) {
                        appName = appName.Remove(indexOfDot);
                    }
                }

                return String.IsNullOrEmpty(appName) ? "/" : appName;
            }
            catch {
                return "/";
            }
        }

        // We don't trim the param before checking with password parameters
        internal static bool ValidatePasswordParameter(ref string param, int maxSize) {
            if (param == null) {
                return false;
            }

            if (param.Length < 1) {
                return false;
            }

            if (maxSize > 0 && (param.Length > maxSize) ) {
                return false;
            }

            return true;
        }

        internal static bool ValidateParameter(ref string param, int maxSize, bool checkForNull = false, bool checkIfEmpty = false, bool checkForCommas = false) {
            if (param == null) {
                return !checkForNull;
            }

            param = param.Trim();
            if ((checkIfEmpty && param.Length < 1) ||
                 (maxSize > 0 && param.Length > maxSize) ||
                 (checkForCommas && param.Contains(","))) {
                return false;
            }

            return true;
        }

        // We don't trim the param before checking with password parameters
        internal static void CheckPasswordParameter(ref string param, int maxSize, string paramName) {
            if (param == null) {
                throw new ArgumentNullException(paramName);
            }

            if (param.Length < 1) {
                throw new ArgumentException(StringResources.GetString(StringResources.ParameterCanNotBeEmpty, paramName), paramName);
            }

            if (maxSize > 0 && param.Length > maxSize) {
                throw new ArgumentException(StringResources.GetString(StringResources.ParameterTooLong, paramName, maxSize.ToString(CultureInfo.InvariantCulture)), paramName);
            }
        }

        internal static void CheckParameter(ref string param, int maxSize, string paramName, bool checkForNull = false, bool checkIfEmpty = false, bool checkForCommas = false)
        {
            if (param == null) {
                if (checkForNull) {
                    throw new ArgumentNullException(paramName);
                }

                return;
            }

            param = param.Trim();
            if (checkIfEmpty && param.Length < 1) {
                throw new ArgumentException(StringResources.GetString(StringResources.ParameterCanNotBeEmpty, paramName), paramName);
            }

            if (maxSize > 0 && param.Length > maxSize) {
                throw new ArgumentException(StringResources.GetString(StringResources.ParameterTooLong, paramName, maxSize.ToString(CultureInfo.InvariantCulture)), paramName);
            }

            if (checkForCommas && param.Contains(",")) {
                throw new ArgumentException(StringResources.GetString(StringResources.ParameterCanNotContainComma, paramName), paramName);
            }
        }

        internal static void CheckArrayParameter(ref string[] param, bool checkForNull, bool checkIfEmpty, bool checkForCommas, int maxSize, string paramName) {
            if (param == null) {
                throw new ArgumentNullException(paramName);
            }

            if (param.Length < 1) {
                throw new ArgumentException(StringResources.GetString(StringResources.ParameterArrayEmpty, paramName), paramName);
            }

            var values = new Hashtable(param.Length);
            for (int i = param.Length - 1; i >= 0; i--) {
                CheckParameter(ref param[i], maxSize,
                    paramName + "[ " + i.ToString(CultureInfo.InvariantCulture) + " ]", checkForNull, checkIfEmpty, checkForCommas);
                if (values.Contains(param[i])) {
                    throw new ArgumentException(StringResources.GetString(StringResources.ParameterDuplicateArrayElement, paramName), paramName);
                }
                values.Add(param[i], param[i]);
            }
        }

        internal static bool GetBooleanValue(NameValueCollection config, string valueName, bool defaultValue) {
            string sValue = config[valueName];
            if (sValue == null) {
                return defaultValue;
            }

            bool result;
            if (bool.TryParse(sValue, out result)) {
                return result;
            }
            throw new ProviderException(StringResources.GetString(StringResources.ValueMustBeBoolean, valueName));
        }

        internal static int GetIntValue(NameValueCollection config, string valueName, int defaultValue, bool zeroAllowed, int maxValueAllowed) {
            string sValue = config[valueName];

            if (sValue == null) {
                return defaultValue;
            }

            int iValue;
            if (!Int32.TryParse(sValue, out iValue)) {
                if (zeroAllowed) {
                    throw new ProviderException(StringResources.GetString(StringResources.ValueMustBeNonNegativeInteger, valueName));
                }

                throw new ProviderException(StringResources.GetString(StringResources.ValueMustBePositiveInteger, valueName));
            }

            if (zeroAllowed && iValue < 0) {
                throw new ProviderException(StringResources.GetString(StringResources.ValueMustBeNonNegativeInteger, valueName));
            }

            if (!zeroAllowed && iValue <= 0) {
                throw new ProviderException(StringResources.GetString(StringResources.ValueMustBePositiveInteger, valueName));
            }

            if (maxValueAllowed > 0 && iValue > maxValueAllowed) {
                throw new ProviderException(StringResources.GetString(StringResources.ValueTooBig, valueName, maxValueAllowed.ToString(CultureInfo.InvariantCulture)));
            }

            return iValue;
        }

        private static bool IsDirectorySeparatorChar(char ch) {
            return (ch == '\\' || ch == '/');
        }

        internal static bool IsAbsolutePhysicalPath(string path) {
            if (path == null || path.Length < 3)
                return false;

            // e.g c:\foo
            if (path[1] == ':' && IsDirectorySeparatorChar(path[2]))
                return true;

            // e.g \\server\share\foo or //server/share/foo
            return IsUncSharePath(path);
        }

        internal static bool IsUncSharePath(string path) {
            // e.g \\server\share\foo or //server/share/foo
            if (path.Length > 2 && IsDirectorySeparatorChar(path[0]) && IsDirectorySeparatorChar(path[1]))
                return true;
            return false;

        }

        internal static XmlNode GetAndRemoveBooleanAttribute(XmlNode node, string attrib, ref bool val) {
            return GetAndRemoveBooleanAttributeInternal(node, attrib, false /*fRequired*/, ref val);
        }

        // input.Xml cursor must be at a true/false XML attribute
        private static XmlNode GetAndRemoveBooleanAttributeInternal(XmlNode node, string attrib, bool fRequired, ref bool val) {
            XmlNode a = GetAndRemoveAttribute(node, attrib, fRequired);
            if (a != null) {
                if (a.Value == "true") {
                    val = true;
                }
                else if (a.Value == "false") {
                    val = false;
                }
                else {
                    throw new ConfigurationErrorsException(
                                    StringResources.GetString(StringResources.InvalidBooleanAttribute, a.Name),
                                    a);
                }
            }

            return a;
        }

        private static XmlNode GetAndRemoveAttribute(XmlNode node, string attrib, bool fRequired)
        {
            if (node.Attributes == null)
            {
                return null;
            }

            XmlNode a = node.Attributes.RemoveNamedItem(attrib);

            // If the attribute is required and was not present, throw
            if (fRequired && a == null) {
                throw new ConfigurationErrorsException(
                    StringResources.GetString(StringResources.MissingRequiredAttribute, attrib, node.Name),
                    node);
            }

            return a;
        }

        internal static XmlNode GetAndRemoveNonEmptyStringAttribute(XmlNode node, string attrib, ref string val) {
            return GetAndRemoveNonEmptyStringAttributeInternal(node, attrib, false /*fRequired*/, ref val);
        }

        private static XmlNode GetAndRemoveNonEmptyStringAttributeInternal(XmlNode node, string attrib, bool fRequired, ref string val) {
            XmlNode a = GetAndRemoveStringAttributeInternal(node, attrib, fRequired, ref val);
            if (a != null && val.Length == 0) {
                throw new ConfigurationErrorsException(
                    StringResources.GetString(StringResources.EmptyAttribute, attrib),
                    a);
            }

            return a;
        }

        private static XmlNode GetAndRemoveStringAttributeInternal(XmlNode node, string attrib, bool fRequired, ref string val) {
            XmlNode a = GetAndRemoveAttribute(node, attrib, fRequired);
            if (a != null) {
                val = a.Value;
            }

            return a;
        }

        internal static void CheckForUnrecognizedAttributes(XmlNode node)
        {
            if (node.Attributes != null)
                if (node.Attributes.Count != 0) {
                    throw new ConfigurationErrorsException(
                        StringResources.GetString(StringResources.ConfigBaseUnrecognizedAttribute, node.Attributes[0].Name),
                        node.Attributes[0]);
                }
        }

        internal static void CheckForNonCommentChildNodes(XmlNode node) {
            foreach (XmlNode childNode in node.ChildNodes) {
                if (childNode.NodeType != XmlNodeType.Comment) {
                    throw new ConfigurationErrorsException(
                                    StringResources.GetString(StringResources.ConfigBaseNoChildNodes),
                                    childNode);
                }
            }
        }

        internal static XmlNode GetAndRemoveStringAttribute(XmlNode node, string attrib, ref string val) {
            return GetAndRemoveStringAttributeInternal(node, attrib, false /*fRequired*/, ref val);
        }

        internal static void CheckForbiddenAttribute(XmlNode node, string attrib) {
            if (node.Attributes != null)
            {
                var attr = node.Attributes[attrib];
                if (attr != null) {
                    throw new ConfigurationErrorsException(
                        StringResources.GetString(StringResources.ConfigBaseUnrecognizedAttribute, attrib),
                        attr);
                }
            }
        }

        // Returns whether the virtual path is relative.  Note that this returns true for
        // app relative paths (e.g. "~/sub/foo.aspx")
        internal static bool IsRelativeUrl(string virtualPath) {
            // If it has a protocol, it's not relative
            if (virtualPath.IndexOf(":", StringComparison.Ordinal) != -1)
                return false;

            return !IsRooted(virtualPath);
        }

        internal static bool IsRooted(String basepath) {
            return (String.IsNullOrEmpty(basepath) || basepath[0] == '/' || basepath[0] == '\\');
        }

        internal static void GetAndRemoveStringAttribute(NameValueCollection config, string attrib, string providerName, ref string val) {
            val = config.Get(attrib);
            config.Remove(attrib);
        }

        internal static void CheckUnrecognizedAttributes(NameValueCollection config, string providerName) {
            if (config.Count > 0) {
                string attribUnrecognized = config.GetKey(0);
                if (!String.IsNullOrEmpty(attribUnrecognized))
                    throw new ConfigurationErrorsException(
                                    StringResources.GetString(StringResources.UnexpectedProviderAttribute, attribUnrecognized, providerName));
            }
        }

        internal static string GetStringFromBool(bool flag) {
            return flag ? "true" : "false";
        }
        internal static void GetAndRemovePositiveOrInfiniteAttribute(NameValueCollection config, string attrib, string providerName, ref int val)
        {
            GetPositiveOrInfiniteAttribute(config, attrib, providerName, ref val);
            config.Remove(attrib);
        }

        internal static void GetPositiveOrInfiniteAttribute(NameValueCollection config, string attrib, string providerName, ref int val)
        {
            string s = config.Get(attrib);
            int t;

            if (s == null)
            {
                return;
            }

            if (s == "Infinite")
            {
                t = Infinite;
            }
            else
            {
                try
                {
                    t = Convert.ToInt32(s, CultureInfo.InvariantCulture);
                }
                catch (Exception e)
                {
                    if (e is ArgumentException || e is FormatException || e is OverflowException)
                    {
                        throw new ConfigurationErrorsException(
                            StringResources.GetString(StringResources.InvalidProviderPositiveAttributes, attrib, providerName));
                    }
                    throw;
                }

                if (t < 0)
                {
                    throw new ConfigurationErrorsException(
                        StringResources.GetString(StringResources.InvalidProviderPositiveAttributes, attrib, providerName));

                }
            }

            val = t;
        }

        internal static void GetAndRemovePositiveAttribute(NameValueCollection config, string attrib, string providerName, ref int val)
        {
            GetPositiveAttribute(config, attrib, providerName, ref val);
            config.Remove(attrib);
        }

        internal static void GetPositiveAttribute(NameValueCollection config, string attrib, string providerName, ref int val)
        {
            string s = config.Get(attrib);
            int t;

            if (s == null)
            {
                return;
            }

            try
            {
                t = Convert.ToInt32(s, CultureInfo.InvariantCulture);
            }
            catch (Exception e)
            {
                if (e is ArgumentException || e is FormatException || e is OverflowException)
                {
                    throw new ConfigurationErrorsException(
                        StringResources.GetString(StringResources.InvalidProviderPositiveAttributes, attrib, providerName));
                }
                throw;
            }

            if (t < 0)
            {
                throw new ConfigurationErrorsException(
                    StringResources.GetString(StringResources.InvalidProviderPositiveAttributes, attrib, providerName));

            }

            val = t;
        }
    }
}
